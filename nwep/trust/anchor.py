"""anchor is the quorum checkpoint producer of the trust layer NW120600 NW120900.

an AnchorNode is one member of the anchor set. it answers peers' partial-signature
requests (the respond side, routed through dispatch from a server handler) and,
acting as coordinator for an epoch, gathers partials from peers and aggregates
them into a checkpoint (the coordinate side). a checkpoint binds an epoch's merkle
root, signed by a quorum of anchors. needs the full libnwep.so (trust), see
nwep.trust.available().
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional, Sequence

from .. import _sys
from ..errors import check
from ..identity import Identity, NodeId
from .bls import BlsKeypair, _require_trust

if TYPE_CHECKING:
    from ..client import Client
    from ..server import Reply, Request, Responder

ffi = _sys.ffi
lib = _sys.lib

_BLS_PK = _sys.BLS_PUBKEY_SIZE
_SIG = _sys.BLS_SIGNATURE_SIZE
_ROOT = 32

# the partial-sig collection window the spec fixes (55 minutes, spec 12.9).
DEFAULT_COLLECTION_WINDOW_MS = 3_300_000

_ENCODE_CAP = 4096


@dataclass(frozen=True, slots=True)
class PartialSig:
    """PartialSig is one anchor's share of a checkpoint signature NW120600.

    the 1-based share index and the 96-byte bls signature over the epoch's root.
    a quorum of these aggregates into a checkpoint.
    """

    index: int
    signature: bytes


class AnchorNode:
    """AnchorNode is one member of the checkpoint-signing anchor set NW120900.

    create it from its web/1 identity and its bls share, feed it each epoch's
    verified log root with collect_log_root, then either answer peers' requests
    through dispatch or, as coordinator, produce_partial_sig and finish_checkpoint.
    it owns c memory, so use it as a context manager. drive one from one thread.
    """

    __slots__ = ("_handle", "_closed")

    def __init__(
        self,
        identity: Identity,
        bls_keypair: BlsKeypair,
        share_index: int,
        collection_window_ms: int = DEFAULT_COLLECTION_WINDOW_MS,
    ):
        """creates an anchor node from its identity and bls share NW120900.

        share_index is 1-based (1..n). collection_window_ms is the partial-sig
        gathering window. the key material is copied into the node, so the
        keypairs may be closed after.

        raises InternalError when creation fails, RuntimeError without trust.
        """
        _require_trust()
        kp = identity._keypair()
        handle = lib.nwep_anchor_node_create(
            kp.pub_,
            kp.priv_,
            bls_keypair._secret_bytes(),
            bls_keypair.public_key,
            share_index,
            collection_window_ms,
        )
        if handle == ffi.NULL:
            from ..errors import InternalError

            raise InternalError("anchor node creation failed")
        self._handle = handle
        self._closed = False

    def collect_log_root(
        self,
        epoch: int,
        server_root: bytes,
        server_log_size: int,
        local_root: bytes,
    ) -> None:
        """records an epoch's log root, cross-checked against the local replica NW120900.

        the anchor will not sign a partial for an epoch whose root it has not
        collected. server_root is a /log/root?epoch=N snapshot the embedder
        fetched; local_root is the anchor's own replica at that epoch.

        raises TrustError (log-corrupt) when the roots disagree, ValueError on a
        wrong-length root.
        """
        self._check_open()
        _expect(server_root, _ROOT, "server_root")
        _expect(local_root, _ROOT, "local_root")
        check(
            lib.nwep_anchor_node_collect_log_root(
                self._handle, epoch, server_root, server_log_size, local_root
            )
        )

    def dispatch(
        self,
        request: "Request",
        responder: "Responder",
        anchor_ids: Sequence[NodeId],
        now_secs: int,
    ) -> Optional["Reply"]:
        """answers a peer's /anchor/partial-sig request, if it is one NW120900.

        the sub-router terminal, like the log server: returns a Reply when the
        request was an /anchor/partial-sig route (answered), or None when it was
        not, leaving the responder for the handler. anchor_ids is the current
        anchor set's node_ids, used to authorize the requester.

        returns a Reply when handled, or None when not an anchor route.
        raises an error from the transport on a dispatch failure.
        """
        from ..server import Reply

        ids_blob = b"".join(bytes(nid) for nid in anchor_ids)
        rc = lib.nwep_anchor_node_dispatch(
            self._handle,
            bytes(request.peer_node_id),
            ids_blob,
            len(anchor_ids),
            request._raw_message(),
            responder._buf,
            now_secs,
        )
        if rc == 0:
            responder._claim()
            return Reply()
        if rc == 1:
            return None
        check(rc)
        return None

    def produce_partial_sig(
        self, epoch: int, merkle_root: bytes, log_size: int
    ) -> PartialSig:
        """produces this anchor's own partial signature for an epoch NW120600.

        the coordinator's own contribution, gathered the same way it answers a
        peer. requires the epoch's root to have been collected first.

        returns this anchor's PartialSig.
        raises TrustError when the epoch root was not collected, ValueError on a
        wrong-length root.
        """
        self._check_open()
        _expect(merkle_root, _ROOT, "merkle_root")
        out_index = ffi.new("uint8_t *")
        out_sig = ffi.new("uint8_t[]", _SIG)
        check(
            lib.nwep_anchor_node_produce_partial_sig(
                self._handle, epoch, merkle_root, log_size, out_index, out_sig
            )
        )
        return PartialSig(int(out_index[0]), bytes(ffi.buffer(out_sig, _SIG)))

    @property
    def raw(self) -> "_sys.CData":
        """returns the raw c nwep_anchor_node pointer, the escape hatch NWG0200."""
        return self._handle

    def close(self) -> None:
        """frees the anchor node. idempotent, also done on context exit."""
        if not self._closed:
            lib.nwep_anchor_node_free(self._handle)
            self._closed = True

    def _check_open(self) -> None:
        if self._closed:
            raise ValueError("anchor node is closed")

    def __enter__(self) -> "AnchorNode":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def __repr__(self) -> str:
        return "AnchorNode(closed)" if self._closed else "AnchorNode(open)"


def request_partial_sig(
    client: "Client",
    epoch: int,
    merkle_root: bytes,
    log_size: int,
    peer_bls_pubkey: bytes,
) -> PartialSig:
    """requests one peer anchor's partial signature over a connection NW120900.

    the coordinate side: issues the request over client and verifies the answer
    against peer_bls_pubkey before returning. client must be connected to the peer
    anchor.

    returns the peer's verified PartialSig.
    raises AppError (forbidden) when the peer declines, CryptoError when the
    signature is bad, ValueError on a wrong-length argument.
    """
    _require_trust()
    _expect(merkle_root, _ROOT, "merkle_root")
    _expect(peer_bls_pubkey, _BLS_PK, "peer_bls_pubkey")
    out_index = ffi.new("uint8_t *")
    out_sig = ffi.new("uint8_t[]", _SIG)
    check(
        lib.nwep_anchor_request_partial_sig(
            client.raw,
            epoch,
            merkle_root,
            log_size,
            peer_bls_pubkey,
            out_index,
            out_sig,
        )
    )
    return PartialSig(int(out_index[0]), bytes(ffi.buffer(out_sig, _SIG)))


def finish_checkpoint(
    epoch: int,
    merkle_root: bytes,
    log_size: int,
    partials: Sequence[PartialSig],
    anchor_bls_pubkeys: Sequence[bytes],
) -> bytes:
    """aggregates gathered partials into a checkpoint for WRITE /log/checkpoint NW120900.

    anchor_bls_pubkeys is the ordered anchor set (each partial's index is 1-based
    into it). a quorum of partials is required.

    returns the encoded checkpoint bytes.
    raises TrustError (threshold) when too few partials, ValueError on a
    wrong-length argument, RuntimeError without the trust layer.
    """
    _require_trust()
    _expect(merkle_root, _ROOT, "merkle_root")
    if not partials:
        raise ValueError("finish_checkpoint needs at least one partial signature")
    indices = bytes(p.index for p in partials)
    sigs = bytearray()
    for p in partials:
        _expect(p.signature, _SIG, "partial signature")
        sigs += p.signature
    pks = bytearray()
    for pk in anchor_bls_pubkeys:
        _expect(pk, _BLS_PK, "anchor bls pubkey")
        pks += pk

    out = ffi.new("uint8_t[]", _ENCODE_CAP)
    outlen = ffi.new("size_t *", _ENCODE_CAP)
    check(
        lib.nwep_anchor_finish_checkpoint(
            epoch,
            merkle_root,
            log_size,
            indices,
            bytes(sigs),
            len(partials),
            bytes(pks),
            len(anchor_bls_pubkeys),
            out,
            outlen,
        )
    )
    return bytes(ffi.buffer(out, outlen[0]))


def _expect(buf: bytes, size: int, name: str) -> None:
    """raises ValueError when a byte argument is not the exact expected length."""
    if len(buf) != size:
        raise ValueError(f"{name} must be {size} bytes, got {len(buf)}")
