"""anchor-node tests NW120600 NW120900: the quorum produces a verifiable checkpoint.

these need the full libnwep.so; the module is skipped on a core-only build. the
networked coordinate path (request_partial_sig over a connection) needs a live
peer anchor and is exercised by the rust binding's multi-node test; here the local
production path is driven to completion: each anchor produces its own partial, the
coordinator aggregates them with finish_checkpoint, and the result verifies against
a trust store seeded with the anchors' bls keys.
"""

from __future__ import annotations

import pytest

import nwep
import nwep.trust as trust

pytestmark = pytest.mark.skipif(
    not trust.available(),
    reason="trust layer absent (NWEP_LIB=core is set); the shipped default has it",
)

from nwep import Identity  # noqa: E402
from nwep.trust import (  # noqa: E402
    AnchorNode,
    BlsKeypair,
    PartialSig,
    TrustStore,
    finish_checkpoint,
)

EPOCH = 1
EPOCH_SECS = 3600  # CHECKPOINT_EPOCH_SECS; a checkpoint's ts is epoch * this.
LOG_SIZE = 7
ROOT = bytes(range(32))


def _anchors(n: int):
    """builds n anchors (identity + bls share, 1-based index) and their bls pubkeys."""
    identities = [Identity.generate() for _ in range(n)]
    bls = [BlsKeypair.generate() for _ in range(n)]
    nodes = [AnchorNode(identities[i], bls[i], share_index=i + 1) for i in range(n)]
    pubkeys = [b.public_key for b in bls]
    return identities, bls, nodes, pubkeys


def _close_all(*groups):
    for group in groups:
        for item in group:
            item.close()


def test_quorum_produces_a_checkpoint_that_verifies() -> None:
    identities, bls, nodes, pubkeys = _anchors(3)
    try:
        # each anchor records the epoch root (its replica matches the server's),
        # then signs its partial over that root.
        partials = []
        for node in nodes:
            node.collect_log_root(EPOCH, ROOT, LOG_SIZE, ROOT)
            partials.append(node.produce_partial_sig(EPOCH, ROOT, LOG_SIZE))

        assert all(
            isinstance(p, PartialSig) and len(p.signature) == 96 for p in partials
        )
        assert sorted(p.index for p in partials) == [1, 2, 3]

        # the coordinator aggregates the partials into a checkpoint.
        checkpoint = finish_checkpoint(EPOCH, ROOT, LOG_SIZE, partials, pubkeys)
        assert len(checkpoint) > 0

        # it verifies against a store seeded with the anchor set, at the epoch's
        # own time (timestamp == epoch * EPOCH_SECS makes it fresh).
        now = EPOCH * EPOCH_SECS
        with TrustStore() as store:
            store.load_genesis_anchors(pubkeys)
            store.verify_checkpoint(checkpoint, now)  # raises if invalid.
            status = store.update_checkpoint(checkpoint, now)
            assert status in (
                trust.CheckpointStatus.FRESH,
                trust.CheckpointStatus.WARNING,
            )
    finally:
        _close_all(nodes, bls, identities)


def test_a_forged_root_does_not_verify() -> None:
    identities, bls, nodes, pubkeys = _anchors(3)
    try:
        partials = []
        for node in nodes:
            node.collect_log_root(EPOCH, ROOT, LOG_SIZE, ROOT)
            partials.append(node.produce_partial_sig(EPOCH, ROOT, LOG_SIZE))

        # the partials signed ROOT; a checkpoint claiming a different root is
        # either rejected at finish or fails to verify against the anchor set.
        forged_root = bytes([0x11] * 32)
        now = EPOCH * EPOCH_SECS
        with TrustStore() as store:
            store.load_genesis_anchors(pubkeys)
            try:
                forged = finish_checkpoint(
                    EPOCH, forged_root, LOG_SIZE, partials, pubkeys
                )
            except nwep.NwepError:
                return  # rejected at aggregation; the forgery never formed.
            with pytest.raises(nwep.NwepError):
                store.verify_checkpoint(forged, now)
    finally:
        _close_all(nodes, bls, identities)


def test_too_few_partials_is_a_threshold_error() -> None:
    identities, bls, nodes, pubkeys = _anchors(3)
    try:
        # a single partial cannot meet the quorum the anchor set requires.
        nodes[0].collect_log_root(EPOCH, ROOT, LOG_SIZE, ROOT)
        one = [nodes[0].produce_partial_sig(EPOCH, ROOT, LOG_SIZE)]
        with pytest.raises(nwep.TrustError):
            checkpoint = finish_checkpoint(EPOCH, ROOT, LOG_SIZE, one, pubkeys)
            # if it produced bytes, they must at least fail verification.
            with TrustStore() as store:
                store.load_genesis_anchors(pubkeys)
                store.verify_checkpoint(checkpoint, EPOCH * EPOCH_SECS)
    finally:
        _close_all(nodes, bls, identities)


def test_collect_log_root_rejects_a_replica_mismatch() -> None:
    identities, bls, nodes, pubkeys = _anchors(1)
    try:
        # the anchor cross-checks the server's epoch root against its own replica;
        # a disagreement is fatal (a log-corruption signal, spec 12.9).
        local = bytes([0x22] * 32)
        with pytest.raises(nwep.TrustError):
            nodes[0].collect_log_root(EPOCH, ROOT, LOG_SIZE, local)
    finally:
        _close_all(nodes, bls, identities)
