"""identity is the cryptographic identity layer, NodeId and Identity NW040200 NW090500.

NodeId is the 32-byte sha-256(pubkey + "WEB/1") that names a node on the network
and in the dht. it is an immutable value, cheap to copy and hash. Identity is an
ed25519 keypair and the NodeId it derives to, what a server or client proves
ownership of in the handshake NW090000. Identity holds a private key, so it keeps
it in c-owned memory and wipes it on close NWG0700, and is a context manager.
"""

from __future__ import annotations

from . import _sys
from .errors import check

ffi = _sys.ffi
lib = _sys.lib


class NodeId:
    """NodeId is the 32-byte sha-256 identity that names a node NW040200.

    it is the public half of an Identity and the key the dht resolves to an
    address. it is an immutable value: str(node_id) is its base58 form, bytes is
    the raw 32 bytes, and two are equal when their bytes match.
    """

    __slots__ = ("_bytes",)

    def __init__(self, raw: bytes):
        """wraps 32 raw bytes as a node_id without checking they name a real key.

        use NodeId.from_pubkey or NodeId.from_base58 to obtain a checked one.
        raises ValueError when raw is not exactly 32 bytes.
        """
        if len(raw) != _sys.NODEID_SIZE:
            raise ValueError(
                f"node_id must be {_sys.NODEID_SIZE} bytes, got {len(raw)}"
            )
        self._bytes = bytes(raw)

    @classmethod
    def from_pubkey(cls, pubkey: bytes) -> "NodeId":
        """derives the node_id of an ed25519 public key, sha-256(pubkey + "WEB/1").

        recovers the name of a key whose raw bytes do not carry it, for example
        one loaded from a pem NW040200.

        returns the derived NodeId.
        raises CryptoError when pubkey is not a valid ed25519 point, ValueError on
        a wrong-length key.
        """
        _expect(pubkey, _sys.PUBKEY_SIZE, "pubkey")
        out = ffi.new("nwep_node_id *")
        check(lib.nwep_nodeid_from_pubkey(out, pubkey))
        return cls(bytes(ffi.buffer(out.bytes, _sys.NODEID_SIZE)))

    @classmethod
    def from_base58(cls, text: str) -> "NodeId":
        """parses a base58 node_id string, the inverse of base58().

        returns the decoded NodeId.
        raises ProtocolError when text is not valid base58 of a 32-byte id.
        """
        out = ffi.new("nwep_node_id *")
        raw = text.encode("ascii")
        check(lib.nwep_nodeid_from_base58(out, raw, len(raw)))
        return cls(bytes(ffi.buffer(out.bytes, _sys.NODEID_SIZE)))

    def base58(self) -> str:
        """encodes this node_id as a base58 string.

        a 32-byte id is at most 44 base58 characters, so this never fails. also
        what str(node_id) returns.
        """
        out = ffi.new("char[64]")
        outlen = ffi.new("size_t *", 64)
        check(lib.nwep_nodeid_to_base58(out, outlen, self._raw()))
        return ffi.string(out, outlen[0]).decode("ascii")

    def verify(self, pubkey: bytes) -> bool:
        """checks that pubkey is the key this node_id was derived from NW040200.

        constant time, so it leaks nothing about the comparison.
        returns True when node_id equals sha-256(pubkey + "WEB/1").
        raises ValueError when pubkey is not 32 bytes.
        """
        _expect(pubkey, _sys.PUBKEY_SIZE, "pubkey")
        return lib.nwep_nodeid_verify(self._raw(), pubkey) == 0

    def _raw(self) -> "_sys.CData":
        """builds a fresh c nwep_node_id from these bytes, for handing to the abi."""
        out = ffi.new("nwep_node_id *")
        ffi.memmove(out.bytes, self._bytes, _sys.NODEID_SIZE)
        return out

    def __bytes__(self) -> bytes:
        return self._bytes

    def __str__(self) -> str:
        return self.base58()

    def __repr__(self) -> str:
        return f"NodeId({self.base58()})"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, NodeId) and other._bytes == self._bytes

    def __hash__(self) -> int:
        return hash(self._bytes)


class Identity:
    """Identity is an ed25519 keypair and the NodeId it derives to NW040200.

    it is what a server or client uses to prove ownership of its node_id in the
    handshake NW090000. it holds a private key in c-owned memory and wipes it via
    nwep_zeroize on close NWG0700, so use it as a context manager or call
    close() when done:

        with Identity.generate() as identity:
            print(identity.node_id)
    """

    __slots__ = ("_kp", "_node_id", "_closed")

    def __init__(self, _kp: "_sys.CData", node_id: NodeId):
        """wraps an already-populated c keypair. use generate() or from_pem()."""
        self._kp = _kp
        self._node_id = node_id
        self._closed = False

    @classmethod
    def generate(cls) -> "Identity":
        """generates a fresh ed25519 identity from the system csprng.

        derives the node_id from the new public key NW040200, so the result is
        ready to bind a server or open a client.

        returns a new Identity.
        raises CryptoError when the csprng or key generation fails.
        """
        out_id = ffi.new("nwep_node_id *")
        kp = ffi.new("nwep_keypair *")
        check(lib.nwep_identity_generate(out_id, kp))
        node_id = NodeId(bytes(ffi.buffer(out_id.bytes, _sys.NODEID_SIZE)))
        return cls(kp, node_id)

    @classmethod
    def from_pem(cls, pem: str) -> "Identity":
        """loads an identity from pkcs#8 pem text, the inverse of to_pem().

        decodes the keypair and re-derives the node_id from its public key, since
        the pem carries the keys but not the name NW040200.

        returns the loaded Identity.
        raises CryptoError when the pem is malformed or not an ed25519 key.
        """
        kp = ffi.new("nwep_keypair *")
        raw = pem.encode("utf-8")
        check(lib.nwep_keypair_load_pem(kp, raw, len(raw)))
        nid = ffi.new("nwep_node_id *")
        try:
            check(lib.nwep_nodeid_from_pubkey(nid, kp.pub_))
        except Exception:
            lib.nwep_zeroize(kp.priv_, _sys.PRIVKEY_SIZE)
            raise
        node_id = NodeId(bytes(ffi.buffer(nid.bytes, _sys.NODEID_SIZE)))
        return cls(kp, node_id)

    def to_pem(self) -> str:
        """encodes this identity to pkcs#8 pem.

        the returned text contains the private key, so it is secret material the
        caller is responsible for protecting and wiping NWG0700.

        returns the pem text.
        raises InternalError when encoding fails.
        """
        self._check_open()
        out = ffi.new("uint8_t[4096]")
        outlen = ffi.new("size_t *", 4096)
        check(lib.nwep_keypair_save_pem(out, outlen, self._kp))
        return bytes(ffi.buffer(out, outlen[0])).decode("utf-8")

    def sign(self, message: bytes) -> bytes:
        """signs a message with this identity's private key NW090500.

        returns the 64-byte ed25519 signature.
        raises CryptoError when signing fails.
        """
        self._check_open()
        sig = ffi.new("uint8_t[64]")
        check(lib.nwep_ed25519_sign(sig, message, len(message), self._kp.priv_))
        return bytes(ffi.buffer(sig, _sys.SIG_SIZE))

    @property
    def node_id(self) -> NodeId:
        """returns the node_id this identity proves ownership of NW040200."""
        return self._node_id

    @property
    def public_key(self) -> bytes:
        """returns the 32-byte ed25519 public key."""
        self._check_open()
        return bytes(ffi.buffer(self._kp.pub_, _sys.PUBKEY_SIZE))

    def close(self) -> None:
        """wipes the private key and disables further use NWG0700.

        idempotent. zeroizes the c-owned key memory through nwep_zeroize so the
        write cannot be optimized away. called automatically on context exit and
        on garbage collection.
        """
        if not self._closed:
            lib.nwep_zeroize(self._kp.priv_, _sys.PRIVKEY_SIZE)
            self._closed = True

    def _keypair(self) -> "_sys.CData":
        """lends the raw c keypair pointer, for handing to a lower layer NWG0700.

        the library copies the keypair internally (server listen, client connect),
        so the pointer is only borrowed for the call.
        """
        self._check_open()
        return self._kp

    def _check_open(self) -> None:
        if self._closed:
            raise ValueError("identity is closed (its private key was wiped)")

    def __enter__(self) -> "Identity":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def __del__(self) -> None:
        # best-effort wipe if the caller never closed it. __slots__ may be
        # partly unset if __init__ raised, so guard the attribute access.
        try:
            self.close()
        except Exception:
            pass

    def __repr__(self) -> str:
        # never render the private key.
        state = "closed" if self._closed else "open"
        return f"Identity(node_id={self._node_id.base58()}, {state})"


def verify_signature(signature: bytes, message: bytes, pubkey: bytes) -> bool:
    """verifies an ed25519 signature over a message against a public key NW090500.

    the standalone counterpart of Identity.sign, for checking a signature whose
    signer's key the caller already holds.

    returns True when the signature is valid.
    raises ValueError on a wrong-length signature or key.
    """
    _expect(signature, _sys.SIG_SIZE, "signature")
    _expect(pubkey, _sys.PUBKEY_SIZE, "pubkey")
    return lib.nwep_ed25519_verify(signature, message, len(message), pubkey) == 0


def _expect(buf: bytes, size: int, name: str) -> None:
    """raises ValueError when a byte argument is not the exact expected length."""
    if len(buf) != size:
        raise ValueError(f"{name} must be {size} bytes, got {len(buf)}")
