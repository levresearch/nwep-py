"""store is the trust state - the anchor set and installed checkpoint NW120700 NW120800.

a TrustStore holds the bls anchor set (seeded from genesis, evolved by
AnchorChange entries) and the latest installed checkpoint, plus the rollback
counter. it is what a node verifies others' keys against: install checkpoints,
check a node's key binding under the trusted checkpoint, ask a log server whether
a key is revoked, and decide whether a rotated key is currently acceptable. needs
the full libnwep.so (trust), see nwep.trust.available().
"""

from __future__ import annotations

from enum import IntEnum
from typing import Optional, Sequence

from .. import _sys
from ..errors import check, from_code
from ..identity import NodeId
from .bls import _require_trust
from .checkpoint import CheckpointStatus

ffi = _sys.ffi
lib = _sys.lib

_BLS_PK = _sys.BLS_PUBKEY_SIZE
_NODEID = _sys.NODEID_SIZE
_PUBKEY = _sys.PUBKEY_SIZE
_COMMIT = 32

# the spec-13 codes evaluate_key_rotation returns as verdicts, not failures.
_IDENTITY_MISMATCH = -502
_IDENTITY_REVOKED = -504

_SAVE_CAP = 8192


class KeyStatus(IntEnum):
    """KeyStatus is whether a node's key is currently revoked NW120800."""

    NOT_REVOKED = 0
    REVOKED = 1


class KeyRotationVerdict(IntEnum):
    """KeyRotationVerdict is whether a presented key is acceptable after a rotation NW120800."""

    ACCEPTABLE = 0  # the new key, or the old key still within its overlap window.
    REVOKED_PAST_OVERLAP = 1  # the old key, used after the overlap expired.
    NOT_RECOGNIZED = 2  # neither the old nor the new key.


class TrustStore:
    """TrustStore is the anchor set + installed checkpoint a node trusts NW120700.

    create one, seed the anchor set with the genesis anchors, then install
    checkpoints and verify keys against it. it owns c memory, so use it as a
    context manager or call close(). drive one store from one thread.
    """

    __slots__ = ("_handle", "_closed")

    def __init__(self):
        """creates an empty trust store.

        seed it with load_genesis_anchors before any non-genesis checkpoint will
        verify.

        raises InternalError when allocation fails, RuntimeError without trust.
        """
        _require_trust()
        handle = lib.nwep_trust_store_create()
        if handle == ffi.NULL:
            from ..errors import InternalError

            raise InternalError("trust store allocation failed")
        self._handle = handle
        self._closed = False

    def load_genesis_anchors(self, pubkeys: Sequence[bytes]) -> None:
        """seeds the anchor set with the genesis anchors' bls pubkeys NW121100.

        each pubkey is 48 bytes; these are the founders' bls public keys from the
        genesis ceremony. required before any non-genesis checkpoint verifies.

        raises ValueError on a wrong-length pubkey, an error from the transport on
        failure.
        """
        self._check_open()
        blob = bytearray()
        for pk in pubkeys:
            _expect(pk, _BLS_PK, "anchor pubkey")
            blob += pk
        check(
            lib.nwep_trust_store_load_genesis_anchors(
                self._handle, bytes(blob), len(pubkeys)
            )
        )

    def update_checkpoint(
        self, checkpoint_bytes: bytes, now_secs: int
    ) -> CheckpointStatus:
        """installs a checkpoint, returning its staleness band NW120700.

        verifies the checkpoint against the anchor set and the equivocation guard,
        then installs it. a STALE checkpoint is rejected, never installed.

        returns the installed checkpoint's CheckpointStatus (FRESH or WARNING).
        raises TrustError (stale-checkpoint, threshold, ...) on rejection.
        """
        self._check_open()
        return CheckpointStatus(
            check(
                lib.nwep_trust_store_update_checkpoint(
                    self._handle, checkpoint_bytes, len(checkpoint_bytes), now_secs
                )
            )
        )

    def verify_checkpoint(self, checkpoint_bytes: bytes, now_secs: int) -> None:
        """verifies a checkpoint against the anchor set without installing it NW120800.

        runs the structural, threshold, and bls-aggregate checks but no
        equivocation guard, and does not mutate the store.

        raises TrustError when the checkpoint does not verify.
        """
        self._check_open()
        check(
            lib.nwep_checkpoint_verify(
                self._handle, checkpoint_bytes, len(checkpoint_bytes), now_secs
            )
        )

    def apply_anchor_change(self, entry_bytes: bytes, current_epoch: int) -> None:
        """applies an AnchorChange log entry to the anchor set NW120300.

        verifies a quorum of distinct current members signed the entry, then
        adds or removes the anchor. the caller must have already checked the
        entry's node_id against a current key binding.

        raises TrustError (threshold, invalid-anchor, ...) on rejection.
        """
        self._check_open()
        check(
            lib.nwep_trust_store_apply_anchor_change(
                self._handle, entry_bytes, len(entry_bytes), current_epoch
            )
        )

    def observe_log_size(self, observed: int) -> None:
        """bumps the rollback counter from a non-checkpoint observation NW121000.

        typically fed a /log/root size; it refuses to go backwards.

        raises TrustError when observed would move the counter backwards.
        """
        self._check_open()
        check(lib.nwep_trust_store_observe_log_size(self._handle, observed))

    @property
    def max_log_size(self) -> int:
        """returns the current rollback-protection log size NW121000."""
        self._check_open()
        return int(lib.nwep_trust_store_max_log_size(self._handle))

    def save(self) -> bytes:
        """serializes the rollback-critical state for persistence NW120700 NW121000.

        captures max_log_size, the equivocation history, and the installed
        checkpoint. the anchor set is NOT included; after load, reload the genesis
        anchors and replay AnchorChange entries.

        returns the serialized blob.
        raises an error from the transport on failure.
        """
        self._check_open()
        return _two_call(
            lambda out, outlen: lib.nwep_trust_store_save(self._handle, out, outlen)
        )

    def load(self, blob: bytes) -> None:
        """restores state written by save() into this store NW120700.

        replaces max_log_size, the equivocation history, and the checkpoint; the
        restored checkpoint is trusted as-is. on malformed input the store is left
        unchanged.

        raises an error from the transport on a malformed blob.
        """
        self._check_open()
        check(lib.nwep_trust_store_load(self._handle, blob, len(blob)))

    def verify_key(
        self,
        client,
        node_id: NodeId,
        now_secs: int,
        recovery_commitment: Optional[bytes] = None,
    ) -> KeyStatus:
        """asks a trusted log server whether a node's key is revoked NW120800 NW121000.

        issues READ /log/revocation/<node_id> over client and validates the
        answer against this store. client must be connected to the trusted log
        server (a no-revocation assertion's server-id is checked against the
        connection's peer). recovery_commitment is node_id's 32-byte key-binding
        commitment, needed to verify a revocation proof.

        returns KeyStatus.NOT_REVOKED or KeyStatus.REVOKED (both verified).
        raises NetworkError / TrustError / CryptoError on a failure.
        """
        self._check_open()
        commitment = (
            recovery_commitment if recovery_commitment is not None else ffi.NULL
        )
        if recovery_commitment is not None:
            _expect(recovery_commitment, _COMMIT, "recovery_commitment")
        rc = check(
            lib.nwep_trust_store_verify_key(
                self._handle, client.raw, bytes(node_id), commitment, now_secs
            )
        )
        return KeyStatus(rc)

    def verify_key_binding(
        self,
        node_id: NodeId,
        expected_pubkey: bytes,
        bundle: bytes,
        now_secs: int,
    ) -> None:
        """verifies a node's key binding under the installed checkpoint NW120800.

        the foundational "this node_id's key is in the trust log under a checkpoint
        i trust" check. bundle is the 169-byte KeyBinding entry followed by its
        encoded merkle inclusion proof.

        raises TrustError / IdentityError / CryptoError when the binding does not
        verify, ValueError on a wrong-length pubkey.
        """
        self._check_open()
        _expect(expected_pubkey, _PUBKEY, "expected_pubkey")
        check(
            lib.nwep_trust_store_verify_key_binding(
                self._handle,
                bytes(node_id),
                expected_pubkey,
                bundle,
                len(bundle),
                now_secs,
            )
        )

    @property
    def raw(self) -> "_sys.CData":
        """returns the raw c nwep_trust_store pointer, the escape hatch NWG0200."""
        return self._handle

    def close(self) -> None:
        """frees the trust store. idempotent, also done on context exit."""
        if not self._closed:
            lib.nwep_trust_store_free(self._handle)
            self._closed = True

    def _check_open(self) -> None:
        if self._closed:
            raise ValueError("trust store is closed")

    def __enter__(self) -> "TrustStore":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def __repr__(self) -> str:
        return (
            "TrustStore(closed)"
            if self._closed
            else f"TrustStore(max_log_size={self.max_log_size})"
        )


def evaluate_key_rotation(
    rotation_bytes: bytes, presented_pubkey: bytes, now_secs: int
) -> KeyRotationVerdict:
    """decides whether a presented key is acceptable after a rotation NW120800.

    rotation_bytes is the raw 241-byte KeyRotation entry (whose proof and
    signatures the caller has already verified). this is a pure decision over that
    entry, so it needs no trust store.

    returns the KeyRotationVerdict: ACCEPTABLE (the new key, or the old key inside
    its overlap window), REVOKED_PAST_OVERLAP, or NOT_RECOGNIZED.
    raises ProtocolError on a malformed entry, ValueError on a wrong-length key,
    RuntimeError without the trust layer.
    """
    _require_trust()
    _expect(presented_pubkey, _PUBKEY, "presented_pubkey")
    rc = lib.nwep_trust_store_evaluate_key_rotation(
        rotation_bytes, len(rotation_bytes), presented_pubkey, now_secs
    )
    if rc == 0:
        return KeyRotationVerdict.ACCEPTABLE
    if rc == _IDENTITY_REVOKED:
        return KeyRotationVerdict.REVOKED_PAST_OVERLAP
    if rc == _IDENTITY_MISMATCH:
        return KeyRotationVerdict.NOT_RECOGNIZED
    raise from_code(rc)


def _two_call(call) -> bytes:
    """runs a two-call-sizing function (NULL out queries size) and returns the bytes."""
    outlen = ffi.new("size_t *", 0)
    check(call(ffi.NULL, outlen))
    size = outlen[0]
    out = ffi.new("uint8_t[]", size)
    outlen[0] = size
    check(call(out, outlen))
    return bytes(ffi.buffer(out, outlen[0]))


def _expect(buf: bytes, size: int, name: str) -> None:
    """raises ValueError when a byte argument is not the exact expected length."""
    if len(buf) != size:
        raise ValueError(f"{name} must be {size} bytes, got {len(buf)}")
