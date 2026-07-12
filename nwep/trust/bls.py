"""bls is the bls12-381 threshold signature primitive of the trust layer NW120500.

a BlsKeypair is a bls secret + public key, the share an anchor signs checkpoints
with. signatures over the same message aggregate into one short signature an
aggregate verify checks against the set of signer pubkeys NW120900. the secret
is 32 bytes of key material held in c memory and wiped on close NWG0700, so a
keypair is a context manager. all of this requires the full libnwep.so (trust),
see nwep.trust.available().
"""

from __future__ import annotations

from typing import Sequence

from .. import _sys
from ..errors import check

ffi = _sys.ffi
lib = _sys.lib

_PK = _sys.BLS_PUBKEY_SIZE
_SK = _sys.BLS_SECKEY_SIZE
_SIG = _sys.BLS_SIGNATURE_SIZE


def _require_trust() -> None:
    """raises a clear error when the loaded library lacks the trust layer NW120000."""
    if not _sys.trust_available():
        raise RuntimeError(
            "the trust layer needs the full libnwep.so (built with blst), but the "
            "trust-less libnwep_core.so is loaded because NWEP_LIB=core was set. "
            "unset it (the default loads libnwep.so), or point NWEP_LIB_DIR at a "
            "directory holding libnwep.so."
        )


class BlsKeypair:
    """BlsKeypair is a bls12-381 secret + public key for threshold signing NW120500.

    generate one with BlsKeypair.generate(); sign() produces a 96-byte signature
    under the domain tag the protocol fixes. the 48-byte public_key is the share
    identity an aggregate verify checks against. holds 32 bytes of secret material
    in c memory and wipes it on close, so use it as a context manager.
    """

    __slots__ = ("_sk", "_pk", "_closed")

    def __init__(self, sk: "_sys.CData", pk: bytes):
        self._sk = sk
        self._pk = pk
        self._closed = False

    @classmethod
    def generate(cls) -> "BlsKeypair":
        """generates a fresh bls12-381 keypair from the system csprng NW120500.

        relies on the trust layer (nwep.trust.available()).

        returns a new BlsKeypair.
        raises CryptoError when key generation fails, RuntimeError when the loaded
        library lacks the trust layer.
        """
        _require_trust()
        sk = ffi.new("uint8_t[]", _SK)
        pk = ffi.new("uint8_t[]", _PK)
        check(lib.nwep_bls_keygen(sk, pk))
        return cls(sk, bytes(ffi.buffer(pk, _PK)))

    def sign(self, message: bytes) -> bytes:
        """signs a message under this keypair's secret NW120500.

        uses the protocol's checkpoint domain tag, so the signature verifies with
        bls_verify and aggregates with bls_aggregate.

        returns the 96-byte bls signature.
        raises CryptoError when signing fails.
        """
        self._check_open()
        out = ffi.new("uint8_t[]", _SIG)
        check(lib.nwep_bls_sign(out, self._sk, message, len(message)))
        return bytes(ffi.buffer(out, _SIG))

    @property
    def public_key(self) -> bytes:
        """returns the 48-byte bls public key, the signer's share identity NW120500."""
        return self._pk

    def _secret_bytes(self) -> bytes:
        """copies out the 32-byte secret, for the genesis ceremony only NW121100.

        the founding secrets are the root of all network trust; this exists so the
        genesis checkpoint helper can gather them, and the caller must dispose of
        the result carefully.
        """
        self._check_open()
        return bytes(ffi.buffer(self._sk, _SK))

    def close(self) -> None:
        """wipes the secret key and disables further signing NWG0700. idempotent."""
        if not self._closed:
            lib.nwep_zeroize(self._sk, _SK)
            self._closed = True

    def _check_open(self) -> None:
        if self._closed:
            raise ValueError("bls keypair is closed (its secret was wiped)")

    def __enter__(self) -> "BlsKeypair":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def __repr__(self) -> str:
        return "BlsKeypair(closed)" if self._closed else "BlsKeypair(open)"


def bls_verify(signature: bytes, public_key: bytes, message: bytes) -> bool:
    """verifies a single-signer bls signature NW120500.

    relies on the trust layer. returns True when the signature is valid for the
    pubkey over the message.
    raises ValueError on a wrong-length signature or pubkey, RuntimeError when the
    loaded library lacks the trust layer.
    """
    _require_trust()
    _expect(signature, _SIG, "signature")
    _expect(public_key, _PK, "public_key")
    return lib.nwep_bls_verify(signature, public_key, message, len(message)) == 0


def bls_aggregate(signatures: Sequence[bytes]) -> bytes:
    """aggregates several bls signatures over one message into a single one NW120900.

    each signature must cover the same message; the result is one 96-byte
    signature an aggregate verify checks against all the signers' pubkeys.

    returns the aggregate signature.
    raises ValueError when no signatures are given or one is the wrong length,
    CryptoError on an aggregation failure, RuntimeError without the trust layer.
    """
    _require_trust()
    if not signatures:
        raise ValueError("bls_aggregate needs at least one signature")
    blob = bytearray()
    for sig in signatures:
        _expect(sig, _SIG, "signature")
        blob += sig
    out = ffi.new("uint8_t[]", _SIG)
    check(lib.nwep_bls_aggregate(out, bytes(blob), len(signatures)))
    return bytes(ffi.buffer(out, _SIG))


def bls_verify_aggregate(
    aggregate_signature: bytes,
    public_keys: Sequence[bytes],
    message: bytes,
) -> bool:
    """verifies an aggregate signature against a set of pubkeys NW120900.

    all pubkeys must have signed the same message. this is the quorum check an
    anchor set's combined checkpoint signature passes.

    returns True when the aggregate is valid for every pubkey over the message.
    raises ValueError when no pubkeys are given or one is the wrong length,
    RuntimeError when the loaded library lacks the trust layer.
    """
    _require_trust()
    _expect(aggregate_signature, _SIG, "aggregate_signature")
    if not public_keys:
        raise ValueError("bls_verify_aggregate needs at least one public key")
    blob = bytearray()
    for pk in public_keys:
        _expect(pk, _PK, "public_key")
        blob += pk
    return (
        lib.nwep_bls_verify_aggregate(
            aggregate_signature, bytes(blob), len(public_keys), message, len(message)
        )
        == 0
    )


def _expect(buf: bytes, size: int, name: str) -> None:
    """raises ValueError when a byte argument is not the exact expected length."""
    if len(buf) != size:
        raise ValueError(f"{name} must be {size} bytes, got {len(buf)}")
