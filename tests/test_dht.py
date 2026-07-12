"""dht slice tests NW110000: bootstrap parse, attach, announce, resolve.

the headline test is a real discover-by-node_id: a rendezvous node, an announcing
peer, and a resolver each run a server + attached dht on their own thread, and the
resolver resolves the peer's address from its node_id alone. each node binds a
distinct 127.0.0.x source ip (ipv4-mapped) so the three do not share one
per-source-ip dht budget  -  the rate limit + return-routability token are keyed on
source ip (a lesson the rust binding learned with loopback swarms).
"""

from __future__ import annotations

import threading
import time

import pytest

import nwep
from nwep import Address, Bootstrap, Client, Dht, Identity, Method, Server, Status


def now_ms() -> int:
    return int(time.monotonic() * 1000)


def now_secs() -> int:
    return int(time.time())


def lo(octet: int, port: int) -> Address:
    # a distinct 127.0.0.x loopback so each node has its own dht source ip.
    return Address.ipv4_mapped(127, 0, 0, octet, port)


class DhtNode:
    """a server with an attached dht, driven on its own thread for a test."""

    def __init__(self, octet: int, port: int, bootstraps, handler=None, announce=None):
        self.identity = Identity.generate()
        builder = Server.builder().identity(self.identity).bind(lo(octet, port))
        if handler is not None:
            builder = builder.on_request(handler)
        self.server = builder.build()
        self.node_id = self.server.node_id
        self.port = self.server.local_port
        self.dht = Dht.attach(self.server, bootstraps)
        self.dht.bootstrap(now_secs())
        self._announce = announce
        self._announced = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self):
        while not self._stop.is_set():
            self.server.tick(now_ms())
            self.dht.tick(now_secs())
            if self._announce is not None and now_secs() - self._announced >= 1:
                self.dht.announce(self._announce, now_secs())
                self._announced = now_secs()
            # fold both timers into one short wait; the dht clock is seconds.
            time.sleep(0.005)

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=2)
        self.dht.close()
        self.server.close()


def test_parse_bootstrap_round_trips_a_node_id() -> None:
    identity = Identity.generate()
    text = f"{identity.node_id.base58()}@[::1]:6937"
    boot = Bootstrap.parse(text)
    assert boot.node_id == identity.node_id


def test_parse_bootstrap_rejects_garbage() -> None:
    with pytest.raises(nwep.ProtocolError):
        Bootstrap.parse("not-a-bootstrap-entry")


def test_bootstrap_of_node_id_and_address() -> None:
    identity = Identity.generate()
    boot = Bootstrap.of(identity.node_id, Address.loopback(6937))
    assert boot.node_id == identity.node_id


def test_attach_requires_a_bootstrap() -> None:
    identity = Identity.generate()
    with (
        Server.builder().identity(identity).bind(Address.loopback(0)).build() as server
    ):
        with pytest.raises(nwep.ConfigError):
            Dht.attach(server, [])


def test_attach_exposes_metrics_and_raw_handle() -> None:
    identity = Identity.generate()
    with (
        Server.builder().identity(identity).bind(Address.loopback(0)).build() as server
    ):
        contact = Bootstrap.of(identity.node_id, Address.loopback(server.local_port))
        with Dht.attach(server, [contact]) as dht:
            assert dht.raw != nwep._ffi.NULL
            m = dht.metrics()
            assert m.datagrams_sent >= 0 and m.datagrams_received >= 0


def test_resolve_by_node_id_through_the_dht() -> None:
    # fixed ports so each node knows the address it announces (an announce must be
    # dialable, so port 0 would be un-announceable).
    r_port, a_port, g_port = 19501, 19502, 19503

    # node R: the rendezvous, self-bootstraps (a harmless self-ping) and routes.
    r_id = Identity.generate()
    r_server = Server.builder().identity(r_id).bind(lo(1, r_port)).build()
    r_contact = Bootstrap.of(r_server.node_id, lo(1, r_port))
    r_dht = Dht.attach(r_server, [r_contact])
    r_dht.bootstrap(now_secs())
    r_stop = threading.Event()

    def r_loop():
        while not r_stop.is_set():
            r_server.tick(now_ms())
            r_dht.tick(now_secs())
            time.sleep(0.005)

    r_thread = threading.Thread(target=r_loop, daemon=True)
    r_thread.start()

    # node A: answers /ping and announces its address through the dht.
    def ping(req, res):
        return res.ok(b"pong") if req.path == "/ping" else res.not_found()

    a = DhtNode(2, a_port, [r_contact], handler=ping, announce=lo(2, a_port))
    a_node = a.node_id

    # the resolver: its own server + dht; resolve A by node_id alone.
    resolver = DhtNode(3, g_port, [r_contact])

    try:
        # let A register its announce with R, then resolve it.
        time.sleep(1.0)
        resolved = None
        resolver.dht.start_lookup(a_node, now_secs())
        for _ in range(200):  # up to ~2s for responses to flow through the loop
            rec = resolver.dht.lookup_result(a_node)
            if rec is not None:
                resolved = rec
                break
            time.sleep(0.01)

        assert resolved is not None, "the dht did not resolve the peer by node_id"
        assert resolved.node_id == a_node
        assert resolved.address.port == a_port

        # connect to the resolved address and exchange a request.
        with (
            Client.builder()
            .identity(Identity.generate())
            .connect(a_node, resolved.address) as client
        ):
            with client.send(Method.READ, "/ping") as resp:
                assert resp.status == Status.OK
                assert resp.body == b"pong"

        assert resolver.dht.metrics().datagrams_received > 0
    finally:
        resolver.stop()
        a.stop()
        r_stop.set()
        r_thread.join(timeout=2)
        r_dht.close()
        r_server.close()
