"""trust-store tests NW120700 NW120800 NW121100: genesis ceremony, install, persistence.

these exercise the trust symbols the shipped libnwep.so carries by default, so they
run under a plain `pytest`; they skip only when NWEP_LIB=core selects the trust-less
build.
"""

from __future__ import annotations

import time

import pytest

import nwep
import nwep.trust as trust

pytestmark = pytest.mark.skipif(
    not trust.available(),
    reason="trust layer absent (NWEP_LIB=core is set); the shipped default has it",
)

from nwep.trust import (  # noqa: E402
    BlsKeypair,
    Checkpoint,
    CheckpointStatus,
    KeyRotationVerdict,
    TrustStore,
    evaluate_key_rotation,
    genesis_checkpoint,
)


def now_secs() -> int:
    return int(time.time())


def _founders(n: int) -> list[BlsKeypair]:
    return [BlsKeypair.generate() for _ in range(n)]


def test_genesis_checkpoint_decodes_and_is_stale_by_wall_clock() -> None:
    founders = _founders(3)
    try:
        cp_bytes = genesis_checkpoint(founders, threshold=2)
        assert len(cp_bytes) > 0
        with Checkpoint.decode(cp_bytes) as cp:
            # the genesis checkpoint's timestamp is epoch 0, so by today's wall
            # clock its raw staleness band is STALE  -  it is the hardcoded
            # bootstrap value, not a live checkpoint.
            assert cp.staleness(now_secs()) is CheckpointStatus.STALE
    finally:
        for f in founders:
            f.close()


def test_genesis_installs_into_a_seeded_store() -> None:
    founders = _founders(3)
    try:
        cp_bytes = genesis_checkpoint(founders, threshold=2)
        anchor_pubkeys = [f.public_key for f in founders]
        with TrustStore() as store:
            store.load_genesis_anchors(anchor_pubkeys)
            # the genesis (epoch 0) install path bypasses the staleness rejection,
            # so it installs and reports a usable band despite the old timestamp.
            status = store.update_checkpoint(cp_bytes, now_secs())
            assert status in (CheckpointStatus.FRESH, CheckpointStatus.WARNING)
    finally:
        for f in founders:
            f.close()


def test_genesis_bypasses_the_anchor_requirement() -> None:
    # the epoch-0 genesis is the trust bootstrap, so both install and standalone
    # verify accept it even before any anchors are loaded NW121100. a
    # non-genesis checkpoint would require the anchor set first.
    founders = _founders(3)
    try:
        cp_bytes = genesis_checkpoint(founders, threshold=2)
        with TrustStore() as store:
            store.update_checkpoint(cp_bytes, now_secs())  # installs via bypass.
        with TrustStore() as store:
            store.verify_checkpoint(cp_bytes, now_secs())  # verifies via bypass.
    finally:
        for f in founders:
            f.close()


def test_observe_log_size_refuses_to_go_backwards() -> None:
    with TrustStore() as store:
        assert store.max_log_size == 0
        store.observe_log_size(10)
        assert store.max_log_size == 10
        store.observe_log_size(20)
        assert store.max_log_size == 20
        with pytest.raises(nwep.TrustError):
            store.observe_log_size(15)  # a rollback is refused.
        assert store.max_log_size == 20


def test_save_load_round_trips_rollback_state() -> None:
    founders = _founders(3)
    try:
        cp_bytes = genesis_checkpoint(founders, threshold=2)
        anchors = [f.public_key for f in founders]
        with TrustStore() as a:
            a.load_genesis_anchors(anchors)
            a.update_checkpoint(cp_bytes, now_secs())
            a.observe_log_size(42)
            blob = a.save()
            assert len(blob) > 0

        with TrustStore() as b:
            # the anchor set is not saved; reload it, then restore the rest.
            b.load_genesis_anchors(anchors)
            b.load(blob)
            assert b.max_log_size == 42
    finally:
        for f in founders:
            f.close()


def test_evaluate_key_rotation_verdicts() -> None:
    from nwep import Identity, KeyRotation

    with Identity.generate() as old, Identity.generate() as new:
        # overlap window open far in the future, so the old key is still accepted.
        entry = KeyRotation.create(
            old.node_id, old, new, now_secs(), now_secs() + 86_400
        )
        assert (
            evaluate_key_rotation(entry, new.public_key, now_secs())
            is KeyRotationVerdict.ACCEPTABLE
        )
        assert (
            evaluate_key_rotation(entry, old.public_key, now_secs())
            is KeyRotationVerdict.ACCEPTABLE
        )

        # a third, unrelated key is recognized as neither.
        with Identity.generate() as stranger:
            assert (
                evaluate_key_rotation(entry, stranger.public_key, now_secs())
                is KeyRotationVerdict.NOT_RECOGNIZED
            )

        # past the overlap expiry, the old key is revoked.
        expired = KeyRotation.create(
            old.node_id, old, new, now_secs() - 1000, now_secs() - 500
        )
        assert (
            evaluate_key_rotation(expired, old.public_key, now_secs())
            is KeyRotationVerdict.REVOKED_PAST_OVERLAP
        )


def test_closed_store_rejects_use() -> None:
    store = TrustStore()
    store.close()
    store.close()  # idempotent.
    with pytest.raises(ValueError):
        store.max_log_size
