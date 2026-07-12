"""identity slice tests NW040200 NW090500: keygen, node_id, base58, sign, pem."""

from __future__ import annotations

import pytest

import nwep
from nwep import Identity, NodeId


def test_generate_then_verify_and_round_trip_base58() -> None:
    with Identity.generate() as identity:
        # the node_id is the binding of the public key.
        assert identity.node_id.verify(identity.public_key)
        # base58 round trips exactly, through str() too.
        text = identity.node_id.base58()
        back = NodeId.from_base58(text)
        assert back == identity.node_id
        assert str(identity.node_id) == text
        assert hash(back) == hash(identity.node_id)


def test_from_pubkey_matches_generated_node_id() -> None:
    with Identity.generate() as identity:
        derived = NodeId.from_pubkey(identity.public_key)
        assert derived == identity.node_id


def test_verify_rejects_a_different_key() -> None:
    with Identity.generate() as a, Identity.generate() as b:
        assert not a.node_id.verify(b.public_key)


def test_sign_produces_a_verifiable_signature() -> None:
    with Identity.generate() as identity:
        message = b"web/1 binding test"
        sig = identity.sign(message)
        assert len(sig) == 64
        # the standalone verify accepts it, and rejects a tampered message + a
        # different signer's key.
        assert nwep.verify_signature(sig, message, identity.public_key)
        assert not nwep.verify_signature(sig, b"tampered", identity.public_key)
        with Identity.generate() as other:
            assert not nwep.verify_signature(sig, message, other.public_key)


def test_pem_round_trips_to_the_same_node_id() -> None:
    with Identity.generate() as identity:
        pem = identity.to_pem()
        assert "PRIVATE KEY" in pem
        with Identity.from_pem(pem) as loaded:
            assert loaded.node_id == identity.node_id
            assert loaded.public_key == identity.public_key


def test_bad_base58_is_an_error_not_a_crash() -> None:
    with pytest.raises(nwep.ProtocolError):
        NodeId.from_base58("not valid base58 !!!")


def test_close_wipes_and_blocks_further_use() -> None:
    identity = Identity.generate()
    node_id = identity.node_id  # the node_id is a value, survives close.
    identity.close()
    identity.close()  # idempotent.
    assert isinstance(node_id, NodeId)
    with pytest.raises(ValueError):
        _ = identity.public_key


def test_node_id_bytes_round_trip() -> None:
    with Identity.generate() as identity:
        raw = bytes(identity.node_id)
        assert len(raw) == 32
        assert NodeId(raw) == identity.node_id


def test_wrong_length_pubkey_is_value_error() -> None:
    with pytest.raises(ValueError):
        NodeId.from_pubkey(b"too short")
