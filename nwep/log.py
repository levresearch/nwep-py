"""log is the merkle trust-log and its entry types NW120200 NW120300, core, no blst.

a Log is an in-memory merkle tree of raw entries with a 32-byte root, the
append-only structure a node publishes its key history into. the three entry
types  -  KeyBinding, KeyRotation, Revocation  -  are the signed records that go in
it: create() produces the encoded wire entry, decode() parses one back into a
typed view. decoding does not verify signatures (use the trust layer's verify
path for that); it is the auditing inverse of create. all of this is in the core
library  -  the merkle log carries no bls dependency.
"""

from __future__ import annotations

import traceback
from dataclasses import dataclass
from enum import IntEnum
from typing import TYPE_CHECKING, Callable, Optional, Union

from . import _sys
from .errors import check
from .identity import Identity, NodeId

if TYPE_CHECKING:
    from .server import Reply, Request, Responder

ffi = _sys.ffi
lib = _sys.lib

_NODEID = _sys.NODEID_SIZE
_PUBKEY = _sys.PUBKEY_SIZE
_COMMIT = 32
_SIG = _sys.SIG_SIZE

# a generous scratch buffer for the fixed-size create outputs (the largest entry,
# a KeyRotation, is 241 bytes).
_ENCODE_CAP = 512


class EntryType(IntEnum):
    """EntryType is the kind of a trust-log entry NW120300.

    returned by entry_type() so a consumer that fetched an arbitrary entry can
    branch to the right decode.
    """

    KEY_BINDING = 1
    KEY_ROTATION = 2
    REVOCATION = 3
    ANCHOR_CHANGE = 4


class RevocationReason(IntEnum):
    """RevocationReason is why a key was revoked NW120300."""

    COMPROMISED = 1
    ROTATION = 2
    DECOMMISSION = 3


def entry_type(entry: bytes) -> EntryType:
    """returns the type of an encoded trust-log entry NW120300.

    lets a consumer that fetched an arbitrary entry branch to the right decode.

    returns the EntryType.
    raises ProtocolError on an unknown type byte, InternalError on empty bytes.
    """
    return EntryType(check(lib.nwep_log_entry_type(entry, len(entry))))


@dataclass(frozen=True, slots=True)
class KeyBinding:
    """KeyBinding registers a node's first key in the log NW120300.

    a decoded view: the node_id (derived from the pubkey), the registered pubkey,
    the recovery commitment sha-256(recovery_pubkey), the timestamp, and the
    ed25519 signature. create() builds the encoded entry; decode() parses one.
    """

    node_id: NodeId
    pubkey: bytes
    recovery_commitment: bytes
    timestamp: int
    signature: bytes

    @staticmethod
    def create(identity: Identity, recovery_commitment: bytes, timestamp: int) -> bytes:
        """builds an encoded KeyBinding entry, signed by identity NW120300.

        registers identity's public key; recovery_commitment is
        sha-256(recovery_pubkey), so the recovery key itself stays offline.

        returns the encoded entry bytes (ready to append to a log).
        raises ValueError on a wrong-length commitment, CryptoError on a sign
        failure.
        """
        _expect(recovery_commitment, _COMMIT, "recovery_commitment")
        kp = identity._keypair()
        return _encode(
            lambda out, outlen: lib.nwep_keybinding_create(
                kp.pub_, recovery_commitment, timestamp, kp.priv_, out, outlen
            )
        )

    @classmethod
    def decode(cls, entry: bytes) -> "KeyBinding":
        """parses an encoded KeyBinding into a typed view NW120300.

        parse only, no signature verification.

        returns the decoded KeyBinding.
        raises ProtocolError when the bytes are too short or the wrong type.
        """
        out = ffi.new("nwep_keybinding *")
        check(lib.nwep_keybinding_decode(entry, len(entry), out))
        return cls(
            node_id=NodeId(bytes(ffi.buffer(out.node_id, _NODEID))),
            pubkey=bytes(ffi.buffer(out.pubkey, _PUBKEY)),
            recovery_commitment=bytes(ffi.buffer(out.recovery_commitment, _COMMIT)),
            timestamp=int(out.timestamp),
            signature=bytes(ffi.buffer(out.signature, _SIG)),
        )


@dataclass(frozen=True, slots=True)
class KeyRotation:
    """KeyRotation rotates a node from an old key to a new one NW120300.

    a decoded view, signed by both keys, with overlap_expiry the unix-seconds
    cutoff after which the old key is rejected.
    """

    node_id: NodeId
    old_pubkey: bytes
    new_pubkey: bytes
    timestamp: int
    overlap_expiry: int
    sig_old: bytes
    sig_new: bytes

    @staticmethod
    def create(
        node_id: NodeId,
        old_identity: Identity,
        new_identity: Identity,
        timestamp: int,
        overlap_expiry: int,
    ) -> bytes:
        """builds an encoded KeyRotation entry, signed by both keys NW120300.

        rotates node_id from old_identity's key to new_identity's key.
        overlap_expiry is the unix-seconds cutoff after which the old key is
        rejected.

        returns the encoded entry bytes.
        raises CryptoError on a sign failure.
        """
        old_kp = old_identity._keypair()
        new_kp = new_identity._keypair()
        return _encode(
            lambda out, outlen: lib.nwep_keyrotation_create(
                bytes(node_id),
                old_kp.pub_,
                new_kp.pub_,
                timestamp,
                overlap_expiry,
                old_kp.priv_,
                new_kp.priv_,
                out,
                outlen,
            )
        )

    @classmethod
    def decode(cls, entry: bytes) -> "KeyRotation":
        """parses an encoded KeyRotation into a typed view NW120300.

        returns the decoded KeyRotation.
        raises ProtocolError when the bytes are too short or the wrong type.
        """
        out = ffi.new("nwep_keyrotation *")
        check(lib.nwep_keyrotation_decode(entry, len(entry), out))
        return cls(
            node_id=NodeId(bytes(ffi.buffer(out.node_id, _NODEID))),
            old_pubkey=bytes(ffi.buffer(out.old_pubkey, _PUBKEY)),
            new_pubkey=bytes(ffi.buffer(out.new_pubkey, _PUBKEY)),
            timestamp=int(out.timestamp),
            overlap_expiry=int(out.overlap_expiry),
            sig_old=bytes(ffi.buffer(out.sig_old, _SIG)),
            sig_new=bytes(ffi.buffer(out.sig_new, _SIG)),
        )


@dataclass(frozen=True, slots=True)
class Revocation:
    """Revocation revokes a key, signed by the offline recovery key NW120300.

    a decoded view carrying the revoked pubkey, the recovery pubkey that signed
    it, and the reason.
    """

    node_id: NodeId
    revoked_pubkey: bytes
    recovery_pubkey: bytes
    reason: RevocationReason
    timestamp: int
    signature: bytes

    @staticmethod
    def create(
        node_id: NodeId,
        revoked_pubkey: bytes,
        recovery_identity: Identity,
        reason: Union[RevocationReason, int],
        timestamp: int,
    ) -> bytes:
        """builds an encoded Revocation entry, signed by the recovery key NW120300.

        revokes revoked_pubkey under node_id; recovery_identity is the offline
        recovery key, whose public half is carried in the entry.

        returns the encoded entry bytes.
        raises ValueError on a wrong-length pubkey, CryptoError on a sign failure.
        """
        _expect(revoked_pubkey, _PUBKEY, "revoked_pubkey")
        kp = recovery_identity._keypair()
        return _encode(
            lambda out, outlen: lib.nwep_revocation_create(
                bytes(node_id),
                revoked_pubkey,
                kp.pub_,
                int(reason),
                timestamp,
                kp.priv_,
                out,
                outlen,
            )
        )

    @classmethod
    def decode(cls, entry: bytes) -> "Revocation":
        """parses an encoded Revocation into a typed view NW120300.

        returns the decoded Revocation.
        raises ProtocolError when the bytes are too short or the wrong type.
        """
        out = ffi.new("nwep_revocation *")
        check(lib.nwep_revocation_decode(entry, len(entry), out))
        return cls(
            node_id=NodeId(bytes(ffi.buffer(out.node_id, _NODEID))),
            revoked_pubkey=bytes(ffi.buffer(out.revoked_pubkey, _PUBKEY)),
            recovery_pubkey=bytes(ffi.buffer(out.recovery_pubkey, _PUBKEY)),
            reason=RevocationReason(out.reason),
            timestamp=int(out.timestamp),
            signature=bytes(ffi.buffer(out.signature, _SIG)),
        )


class Log:
    """Log is an in-memory merkle tree of trust-log entries NW120200.

    append entries and read the 32-byte merkle root; the root is what a checkpoint
    commits to. it hashes each entry as a leaf as-is, with no structural
    validation at this layer. use it as a context manager or call close().
    """

    __slots__ = ("_handle", "_closed")

    def __init__(self):
        """creates an empty in-memory log.

        raises InternalError when allocation fails.
        """
        handle = lib.nwep_log_create()
        if handle == ffi.NULL:
            from .errors import InternalError

            raise InternalError("log allocation failed")
        self._handle = handle
        self._closed = False

    def append(self, entry: bytes) -> int:
        """appends a raw entry as a merkle leaf and returns its index NW120200.

        no structural validation happens here; the entry is hashed as-is.

        returns the new entry's index (0-based).
        raises an error from the transport on an append failure.
        """
        self._check_open()
        return check(lib.nwep_log_append(self._handle, entry, len(entry)))

    @property
    def size(self) -> int:
        """returns the number of entries appended NW120200."""
        self._check_open()
        return int(lib.nwep_log_size(self._handle))

    def root(self) -> bytes:
        """returns the log's current 32-byte merkle root NW120200.

        the value a checkpoint commits to, computable without reading /log/root
        back over the wire.

        returns the 32-byte root.
        raises an error from the transport on failure.
        """
        self._check_open()
        out = ffi.new("uint8_t[]", _NODEID)
        check(lib.nwep_log_root(self._handle, out))
        return bytes(ffi.buffer(out, _NODEID))

    @property
    def raw(self) -> "_sys.CData":
        """returns the raw c nwep_log pointer, the escape hatch to sys NWG0200."""
        return self._handle

    def close(self) -> None:
        """frees the log. idempotent, also done on context exit."""
        if not self._closed:
            lib.nwep_log_free(self._handle)
            self._closed = True

    def _check_open(self) -> None:
        if self._closed:
            raise ValueError("log is closed")

    def __enter__(self) -> "Log":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def __repr__(self) -> str:
        return "Log(closed)" if self._closed else f"Log(size={self.size})"


# the on_append hook callable: (entry_bytes, index) -> None.
AppendHook = Callable[[bytes, int], None]


class LogServer:
    """LogServer routes /log/* requests through the real log endpoints NW000014.

    it is a sub-router: from inside a server handler, hand it the request and
    responder, and it answers the log endpoints (read /log/root, write /log/entry,
    read /log/entry/{i}, ...) or declines so the handler answers the rest. it signs
    responses with the given identity (whose node_id a no-revocation assertion
    binds to, so it should match the quic server's identity) over a borrowed Log
    that must outlive it. use it as a context manager.

        def handle(req, res):
            reply = log_server.dispatch(req, res, now_secs())
            return reply if reply is not None else res.not_found()
    """

    __slots__ = ("_handle", "_log", "_append_cb", "_closed")

    def __init__(self, identity: Identity, log: Log):
        """creates a log server signing with identity over log NW000014.

        log is borrowed and must outlive the server, so this keeps a reference to
        it. the identity's node_id is what a no-revocation assertion's server-id
        binds to, so it should match the quic server's identity.

        raises InternalError when creation fails.
        """
        handle = lib.nwep_log_server_create(identity._keypair(), log.raw)
        if handle == ffi.NULL:
            from .errors import InternalError

            raise InternalError("log server creation failed")
        self._handle = handle
        self._log = log  # keep the borrowed log alive for the server's lifetime.
        self._append_cb: object = None  # keeps the cffi callback alive.
        self._closed = False

    def on_append(self, hook: Optional[AppendHook]) -> None:
        """registers a persistence hook fired for each accepted entry NW000014.

        the hook runs with (entry_bytes, index) after the in-memory append of an
        accepted write /log/entry, before the created response, so an embedder can
        persist entries durably. pass None to clear it. the hook runs on the tick
        thread inside dispatch and must not block; an exception in it is reported
        and swallowed, never unwound into c NWG0900.
        """
        if hook is None:
            lib.nwep_log_server_set_on_append(self._handle, ffi.NULL, ffi.NULL)
            self._append_cb = None
            return

        @ffi.callback("nwep_log_append_fn")
        def trampoline(_ctx, entry, length, index):
            try:
                hook(bytes(ffi.buffer(entry, length)), int(index))
            except Exception:  # no python exception may unwind into c NWG0900.
                traceback.print_exc()

        self._append_cb = trampoline
        lib.nwep_log_server_set_on_append(self._handle, trampoline, ffi.NULL)

    def dispatch(
        self, request: "Request", responder: "Responder", now_secs: int
    ) -> Optional["Reply"]:
        """routes a request through the log endpoints, if it is one NW000014.

        the sub-router terminal: when the request is a /log/* route, it writes the
        response and returns a Reply to return from the handler; when it is not, it
        returns None and leaves the responder untouched for the handler to answer.
        the write endpoints rate-limit per connection using now_secs (unix seconds).

        returns a Reply when handled, or None when it is not a log-server route.
        raises an error from the transport on a dispatch failure.
        """
        from .server import Reply

        rc = lib.nwep_log_server_dispatch(
            self._handle,
            request.conn_id,
            request._raw_message(),
            responder._buf,
            now_secs,
        )
        if rc == 0:
            responder._claim()  # the buf was written; the request is answered.
            return Reply()
        if rc == 1:
            return None  # not a log route; the handler answers it.
        check(rc)  # rc < 0: raise the spec-13 error.
        return None  # unreachable; check() raised.

    @property
    def raw(self) -> "_sys.CData":
        """returns the raw c nwep_log_server pointer, the escape hatch NWG0200."""
        return self._handle

    def close(self) -> None:
        """frees the log server. idempotent, also done on context exit.

        does not free the borrowed Log, which the caller still owns.
        """
        if not self._closed:
            lib.nwep_log_server_free(self._handle)
            self._closed = True
            self._append_cb = None

    def __enter__(self) -> "LogServer":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def __repr__(self) -> str:
        return "LogServer(closed)" if self._closed else "LogServer(open)"


def _encode(call) -> bytes:
    """runs an entry-create call into a scratch buffer and returns the bytes."""
    out = ffi.new("uint8_t[]", _ENCODE_CAP)
    outlen = ffi.new("size_t *", _ENCODE_CAP)
    check(call(out, outlen))
    return bytes(ffi.buffer(out, outlen[0]))


def _expect(buf: bytes, size: int, name: str) -> None:
    """raises ValueError when a byte argument is not the exact expected length."""
    if len(buf) != size:
        raise ValueError(f"{name} must be {size} bytes, got {len(buf)}")


__all__ = [
    "Log",
    "LogServer",
    "EntryType",
    "RevocationReason",
    "KeyBinding",
    "KeyRotation",
    "Revocation",
    "entry_type",
]
