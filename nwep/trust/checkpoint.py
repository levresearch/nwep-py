"""checkpoint is the signed merkle commitment for a trust epoch NW120700 NW121100.

a Checkpoint is the anchor quorum's aggregate-signed statement of the trust log's
merkle root at an epoch, the thing a node installs to bootstrap and advance trust.
this module decodes one from wire bytes and reports its staleness band, and runs
the genesis ceremony that produces the network's epoch-0 checkpoint. verifying and
installing checkpoints against an anchor set lives on TrustStore. needs the full
libnwep.so (trust), see nwep.trust.available().
"""

from __future__ import annotations

from enum import IntEnum
from typing import Sequence

from .. import _sys
from ..errors import check
from .bls import BlsKeypair, _require_trust

ffi = _sys.ffi
lib = _sys.lib

# a generous scratch buffer for the encoded genesis checkpoint (two-call sizing
# also handles a larger one).
_ENCODE_CAP = 4096


class CheckpointStatus(IntEnum):
    """CheckpointStatus is a checkpoint's staleness band NW120700.

    FRESH within the epoch, WARNING past it but tolerated, STALE too old to
    install. update_checkpoint rejects a STALE checkpoint.
    """

    FRESH = 0
    WARNING = 1
    STALE = 2


class Checkpoint:
    """Checkpoint is a decoded epoch checkpoint NW120700.

    decode one from wire bytes with Checkpoint.decode and ask its staleness band.
    it owns c memory, so use it as a context manager or call close(). installing
    or verifying it against an anchor set is done through TrustStore.
    """

    __slots__ = ("_handle", "_closed")

    def __init__(self, handle: "_sys.CData"):
        self._handle = handle
        self._closed = False

    @classmethod
    def decode(cls, data: bytes) -> "Checkpoint":
        """decodes a checkpoint from wire bytes NW120700.

        returns the decoded Checkpoint.
        raises ProtocolError when the bytes are malformed, RuntimeError without the
        trust layer.
        """
        _require_trust()
        out = ffi.new("nwep_checkpoint **")
        check(lib.nwep_checkpoint_decode(data, len(data), out))
        return cls(out[0])

    def staleness(self, now_secs: int) -> CheckpointStatus:
        """returns this checkpoint's staleness band at a time NW120700.

        returns the CheckpointStatus.
        raises an error from the transport on failure.
        """
        self._check_open()
        return CheckpointStatus(
            check(lib.nwep_checkpoint_staleness(self._handle, now_secs))
        )

    @property
    def raw(self) -> "_sys.CData":
        """returns the raw c nwep_checkpoint pointer, the escape hatch NWG0200."""
        return self._handle

    def close(self) -> None:
        """frees the checkpoint. idempotent, also done on context exit."""
        if not self._closed:
            lib.nwep_checkpoint_free(self._handle)
            self._closed = True

    def _check_open(self) -> None:
        if self._closed:
            raise ValueError("checkpoint is closed")

    def __enter__(self) -> "Checkpoint":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def __repr__(self) -> str:
        return "Checkpoint(closed)" if self._closed else "Checkpoint(open)"


def genesis_checkpoint(founders: Sequence[BlsKeypair], threshold: int) -> bytes:
    """runs the genesis ceremony and encodes the network's epoch-0 checkpoint NW121100.

    every founding anchor signs; the aggregate is bls-verified before the bytes
    are produced. the result is the hardcoded genesis that bootstraps trust, and
    the founders' bls public keys are the genesis anchor set a TrustStore loads.
    threshold is the quorum the genesis must satisfy.

    SECURITY: the founders' secrets are the root of all network trust. they are
    read out of the keypairs only for the duration of this call; close the
    keypairs afterward to wipe them NWG0700.

    returns the encoded epoch-0 checkpoint bytes.
    raises CryptoError on a signing or aggregate failure, ValueError on an empty
    founder set, RuntimeError without the trust layer.
    """
    _require_trust()
    if not founders:
        raise ValueError("the genesis ceremony needs at least one founder")
    n = len(founders)
    secrets = b"".join(kp._secret_bytes() for kp in founders)
    pubkeys = b"".join(kp.public_key for kp in founders)
    indices = bytes(range(1, n + 1))  # 1-based share indices.

    out = ffi.new("uint8_t[]", _ENCODE_CAP)
    outlen = ffi.new("size_t *", _ENCODE_CAP)
    check(
        lib.nwep_genesis_checkpoint_create(
            secrets, pubkeys, indices, n, threshold, out, outlen
        )
    )
    return bytes(ffi.buffer(out, outlen[0]))
