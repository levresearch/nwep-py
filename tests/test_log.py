"""trust-log tests NW120200 NW120300, core, no blst: entry create/decode + merkle log.

these run on the core library  -  the merkle log and entry codecs carry no bls
dependency, so they are not gated behind NWEP_LIB=trust.
"""

from __future__ import annotations

import hashlib

import pytest

import nwep
from nwep import (
    EntryType,
    Identity,
    KeyBinding,
    KeyRotation,
    Log,
    Revocation,
    RevocationReason,
    entry_type,
)


def _commitment(recovery: Identity) -> bytes:
    # the recovery commitment is sha-256(recovery_pubkey); the key stays offline.
    return hashlib.sha256(recovery.public_key).digest()


def test_keybinding_create_decode_round_trip() -> None:
    with Identity.generate() as identity, Identity.generate() as recovery:
        commitment = _commitment(recovery)
        entry = KeyBinding.create(identity, commitment, timestamp=1_700_000_000)
        assert len(entry) == 169
        assert entry_type(entry) is EntryType.KEY_BINDING

        decoded = KeyBinding.decode(entry)
        assert decoded.node_id == identity.node_id
        assert decoded.pubkey == identity.public_key
        assert decoded.recovery_commitment == commitment
        assert decoded.timestamp == 1_700_000_000
        assert len(decoded.signature) == 64


def test_keyrotation_create_decode_round_trip() -> None:
    with Identity.generate() as old, Identity.generate() as new:
        node_id = old.node_id
        entry = KeyRotation.create(
            node_id, old, new, timestamp=1_700_000_100, overlap_expiry=1_700_086_500
        )
        assert len(entry) == 241
        assert entry_type(entry) is EntryType.KEY_ROTATION

        decoded = KeyRotation.decode(entry)
        assert decoded.node_id == node_id
        assert decoded.old_pubkey == old.public_key
        assert decoded.new_pubkey == new.public_key
        assert decoded.overlap_expiry == 1_700_086_500
        assert len(decoded.sig_old) == 64 and len(decoded.sig_new) == 64


def test_revocation_create_decode_round_trip() -> None:
    with Identity.generate() as identity, Identity.generate() as recovery:
        entry = Revocation.create(
            identity.node_id,
            identity.public_key,
            recovery,
            RevocationReason.COMPROMISED,
            timestamp=1_700_000_200,
        )
        assert len(entry) == 170
        assert entry_type(entry) is EntryType.REVOCATION

        decoded = Revocation.decode(entry)
        assert decoded.node_id == identity.node_id
        assert decoded.revoked_pubkey == identity.public_key
        assert decoded.recovery_pubkey == recovery.public_key
        assert decoded.reason is RevocationReason.COMPROMISED
        assert decoded.timestamp == 1_700_000_200


def test_entry_type_rejects_garbage() -> None:
    with pytest.raises(nwep.NwepError):
        entry_type(b"\xff not a real entry")


def test_decode_wrong_type_raises() -> None:
    with Identity.generate() as identity, Identity.generate() as recovery:
        binding = KeyBinding.create(identity, _commitment(recovery), 1)
        # a keybinding is not a revocation; decoding it as one must fail.
        with pytest.raises(nwep.ProtocolError):
            Revocation.decode(binding)


def test_merkle_log_append_size_root() -> None:
    with Identity.generate() as identity, Identity.generate() as recovery, Log() as log:
        assert log.size == 0
        empty_root = log.root()
        assert len(empty_root) == 32

        e1 = KeyBinding.create(identity, _commitment(recovery), 1_700_000_000)
        assert log.append(e1) == 0
        assert log.size == 1
        root1 = log.root()
        assert root1 != empty_root  # the root moved when an entry was added.

        e2 = Revocation.create(
            identity.node_id,
            identity.public_key,
            recovery,
            RevocationReason.ROTATION,
            1_700_000_300,
        )
        assert log.append(e2) == 1
        assert log.size == 2
        assert log.root() != root1  # and again.


def test_merkle_root_is_deterministic_for_the_same_entries() -> None:
    with Identity.generate() as identity, Identity.generate() as recovery:
        entry = KeyBinding.create(identity, _commitment(recovery), 1_700_000_000)
        with Log() as a, Log() as b:
            a.append(entry)
            b.append(entry)
            assert a.root() == b.root()  # same leaves -> same merkle root.


def test_closed_log_rejects_use() -> None:
    log = Log()
    log.close()
    log.close()  # idempotent.
    with pytest.raises(ValueError):
        log.append(b"x")
