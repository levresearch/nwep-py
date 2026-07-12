"""dht is the discovery layer, resolving a node_id to an address NW110000.

a Dht attaches to a running Server and reuses its udp socket, so the two share one
fd and one loop. it is the driven layer: announce this node's address, start a
lookup for a peer, then poll lookup_result after the server has absorbed
responses. its clock is unix seconds, distinct from the server's monotonic
milliseconds, so tick(now_secs) takes a different time than the server's tick.

    dht = Dht.attach(server, [Bootstrap.parse("<node>@[::1]:6937")])
    dht.bootstrap(now_secs())
    dht.announce(my_service_addr, now_secs())
    # ... drive server.tick(now_ms) and dht.tick(now_secs) together ...
    dht.start_lookup(peer_node_id, now_secs())
    record = dht.lookup_result(peer_node_id)   # None until responses arrive
"""

from __future__ import annotations

from typing import Iterable, Optional

from . import _sys
from .address import Address
from .errors import check, from_code
from .identity import NodeId
from .server import Server

ffi = _sys.ffi
lib = _sys.lib

# the c miss code for lookup_result and a record that is not present NW110000.
_APP_NOT_FOUND = -601

# republish cadence the spec recommends for a held announce NW110700.
REPUBLISH_INTERVAL_SECS = 1800


class Bootstrap:
    """Bootstrap is a contact used to enter the dht, a node_id + address NW110900.

    parse one from the NW110900 text form "<NodeID_base58>@[<ipv6>]:<port>" with
    Bootstrap.parse, or build it from a node_id and an Address. at least one is
    required to attach a Dht.
    """

    __slots__ = ("_entry",)

    def __init__(self, _entry: "_sys.CData"):
        self._entry = _entry

    @classmethod
    def parse(cls, text: str) -> "Bootstrap":
        """parses a "<NodeID_base58>@[<ipv6>]:<port>" contact string NW110900.

        returns the Bootstrap.
        raises ProtocolError when text is not a well-formed bootstrap entry.
        """
        out = ffi.new("nwep_bootstrap_entry *")
        raw = text.encode("utf-8")
        check(lib.nwep_dht_parse_bootstrap(out, raw, len(raw)))
        return cls(out)

    @classmethod
    def of(cls, node_id: NodeId, address: Address) -> "Bootstrap":
        """builds a bootstrap contact from a node_id and its address NW110900."""
        out = ffi.new("nwep_bootstrap_entry *")
        ffi.memmove(out.node_id.bytes, bytes(node_id), _sys.NODEID_SIZE)
        # address._raw() is a nwep_address *; copy its bytes into out.addr.
        ffi.memmove(
            ffi.addressof(out, "addr"), address._raw(), ffi.sizeof("nwep_address")
        )
        return cls(out)

    @property
    def node_id(self) -> NodeId:
        """returns the node_id of this contact NW040200."""
        return NodeId(bytes(ffi.buffer(self._entry.node_id.bytes, _sys.NODEID_SIZE)))

    def __repr__(self) -> str:
        return f"Bootstrap({self.node_id.base58()})"


class Record:
    """Record is a signed discovery record binding a node_id to an address NW110300.

    the result of a successful lookup: the resolved node_id, its service address,
    the public key the record was signed with, and the announce sequence and
    timestamp. it is an immutable snapshot, owned by the caller.
    """

    __slots__ = ("_node_id", "_addr", "_pubkey", "seq", "timestamp")

    def __init__(self, record: "_sys.CData"):
        self._node_id = NodeId(
            bytes(ffi.buffer(record.node_id.bytes, _sys.NODEID_SIZE))
        )
        addr = ffi.new("nwep_address *")
        # addr and &record.addr are both pointers to the 32-byte address struct.
        ffi.memmove(addr, ffi.addressof(record, "addr"), ffi.sizeof("nwep_address"))
        self._addr = Address(addr)
        self._pubkey = bytes(ffi.buffer(record.pubkey, _sys.PUBKEY_SIZE))
        self.seq: int = int(record.seq)
        self.timestamp: int = int(record.timestamp)

    @property
    def node_id(self) -> NodeId:
        """returns the node_id this record resolves NW110300."""
        return self._node_id

    @property
    def address(self) -> Address:
        """returns the service address the node announced NW110300."""
        return self._addr

    @property
    def pubkey(self) -> bytes:
        """returns the public key the record was signed with NW110300."""
        return self._pubkey

    def __repr__(self) -> str:
        return f"Record({self._node_id.base58()} -> port {self._addr.port}, seq={self.seq})"


class DhtMetrics:
    """DhtMetrics is a snapshot of the dht's traffic counters NW110000.

    the dht shares the server's socket but its datagrams bypass the server send
    path, so server metrics cannot see them  -  read these for the dht half.
    """

    __slots__ = ("datagrams_sent", "datagrams_received", "bytes_sent", "bytes_received")

    def __init__(self, m: "_sys.CData"):
        self.datagrams_sent = int(m.datagrams_sent)
        self.datagrams_received = int(m.datagrams_received)
        self.bytes_sent = int(m.bytes_sent)
        self.bytes_received = int(m.bytes_received)

    def __repr__(self) -> str:
        return f"DhtMetrics(sent={self.datagrams_sent}, received={self.datagrams_received})"


class Dht:
    """Dht is the discovery overlay attached to a Server NW110000.

    attach it to a running server with Dht.attach, then drive tick(now_secs) in
    the same loop as the server's tick (its clock is unix seconds). announce this
    node's address, start_lookup a peer, and poll lookup_result. close() detaches
    it; it never closes the server's socket. drive one Dht from the server's thread.
    """

    __slots__ = ("_handle", "_server", "_closed")

    def __init__(self, handle: "_sys.CData", server: Server):
        self._handle = handle
        self._server = server  # keep the server alive; the dht borrows its socket.
        self._closed = False

    @classmethod
    def attach(
        cls,
        server: Server,
        bootstraps: Iterable[Bootstrap],
        initial_seq: int = 0,
    ) -> "Dht":
        """attaches a dht to a running server, reusing its socket NW110900.

        the dht borrows the server's udp socket and identity, so the server must
        outlive it (this handle keeps a reference to enforce that). bootstraps must
        contain at least one contact. pass the last announced seq from a previous
        run as initial_seq, or 0 on first boot NW110600.

        returns the attached Dht.
        raises ConfigError when no bootstrap is given, and an error from the
        transport when attach fails.
        """
        entries = list(bootstraps)
        if not entries:
            from .errors import ConfigInvalid  # type: ignore[attr-defined]

            raise ConfigInvalid("dht attach needs at least one bootstrap contact")
        array = ffi.new("nwep_bootstrap_entry[]", len(entries))
        for i, b in enumerate(entries):
            ffi.memmove(
                ffi.addressof(array, i),
                b._entry,
                ffi.sizeof("nwep_bootstrap_entry"),
            )
        out = ffi.new("nwep_dht **")
        check(lib.nwep_dht_attach(out, server.raw, array, len(entries), initial_seq))
        return cls(out[0], server)

    def bootstrap(self, now_secs: int) -> None:
        """pings every bootstrap peer to enter the network NW110900.

        responses arrive through the server's tick; call tick(now_secs) after.

        raises an error from the transport when the bootstrap send fails.
        """
        check(lib.nwep_dht_bootstrap(self._handle, now_secs))

    def announce(self, service_addr: Address, now_secs: int) -> None:
        """publishes a signed record binding this node to an address NW110700.

        re-call every REPUBLISH_INTERVAL_SECS to keep the record live.

        raises an error from the transport when the announce send fails.
        """
        check(lib.nwep_dht_announce(self._handle, service_addr._raw(), now_secs))

    def start_lookup(self, target: NodeId, now_secs: int) -> None:
        """begins a find_value lookup for a node_id, returning at once NW110800.

        poll lookup_result after the server has absorbed responses via its tick.

        raises an error from the transport when the lookup send fails.
        """
        check(lib.nwep_dht_start_lookup(self._handle, target._raw(), now_secs))

    def lookup_result(self, target: NodeId) -> Optional[Record]:
        """returns the resolved record for a node_id, or None on a miss NW110800.

        the cached record once a lookup has observed one; None until then. pair it
        with start_lookup and the server's tick.

        returns the Record on a hit, None when none has been observed yet.
        raises a transport error other than the expected not-found miss.
        """
        out = ffi.new("nwep_dht_record *")
        rc = lib.nwep_dht_lookup_result(self._handle, target._raw(), out)
        if rc == 0:
            return Record(out)
        if rc == _APP_NOT_FOUND:
            return None
        raise from_code(rc)

    def tick(self, now_secs: int) -> None:
        """advances the dht's timers (refresh, expiry, retransmit) NW110000.

        call in the same loop as the server's tick, but with a unix-seconds clock.

        raises an error from the transport on a fatal fault.
        """
        check(lib.nwep_dht_tick(self._handle, now_secs))

    def next_timeout(self, now_secs: int) -> Optional[int]:
        """returns ms until the dht's next timer, or None when idle NW110000.

        fold this into the same poll wait as the server's next_timeout (take the
        minimum). None means no transaction is outstanding, so an idle dht costs
        no cpu; 0 means a deadline already passed.
        """
        timeout = lib.nwep_dht_next_timeout_ms(self._handle, now_secs)
        return None if timeout < 0 else timeout

    def metrics(self) -> DhtMetrics:
        """returns a snapshot of the dht's traffic counters NW110000."""
        out = ffi.new("nwep_dht_metrics *")
        check(lib.nwep_dht_metrics_get(self._handle, out))
        return DhtMetrics(out)

    @property
    def raw(self) -> "_sys.CData":
        """returns the raw c nwep_dht pointer, the escape hatch to sys NWG0200."""
        return self._handle

    def close(self) -> None:
        """detaches and frees the dht. does not close the server's socket. idempotent."""
        if not self._closed:
            lib.nwep_dht_close(self._handle)
            self._closed = True

    def __enter__(self) -> "Dht":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def __repr__(self) -> str:
        return "Dht(closed)" if self._closed else "Dht(attached)"


__all__ = ["Bootstrap", "Record", "Dht", "DhtMetrics", "REPUBLISH_INTERVAL_SECS"]
