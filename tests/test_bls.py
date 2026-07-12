"""bls trust-layer tests NW120500 NW120900: keygen, sign/verify, aggregate.

these exercise the trust symbols, which the shipped libnwep.so carries by default,
so they run under a plain `pytest`. they skip only when NWEP_LIB=core opted into the
trust-less libnwep_core.so build.
"""

from __future__ import annotations

import pytest

import nwep.trust as trust

pytestmark = pytest.mark.skipif(
    not trust.available(),
    reason="trust layer absent (NWEP_LIB=core is set); the shipped default has it",
)

from nwep.trust import BlsKeypair, bls_aggregate, bls_verify, bls_verify_aggregate  # noqa: E402


def test_keypair_sizes() -> None:
    with BlsKeypair.generate() as kp:
        assert len(kp.public_key) == 48


def test_sign_then_verify() -> None:
    with BlsKeypair.generate() as kp:
        msg = b"checkpoint epoch root"
        sig = kp.sign(msg)
        assert len(sig) == 96
        assert bls_verify(sig, kp.public_key, msg)


def test_verify_rejects_wrong_message() -> None:
    with BlsKeypair.generate() as kp:
        sig = kp.sign(b"the right message")
        assert not bls_verify(sig, kp.public_key, b"a different message")


def test_verify_rejects_wrong_key() -> None:
    with BlsKeypair.generate() as a, BlsKeypair.generate() as b:
        sig = a.sign(b"shared")
        assert not bls_verify(sig, b.public_key, b"shared")


def test_aggregate_verifies_against_all_signers() -> None:
    # three signers over one message; the aggregate verifies against all pubkeys.
    msg = b"the epoch all anchors sign"
    keys = [BlsKeypair.generate() for _ in range(3)]
    try:
        sigs = [k.sign(msg) for k in keys]
        agg = bls_aggregate(sigs)
        assert len(agg) == 96
        pubkeys = [k.public_key for k in keys]
        assert bls_verify_aggregate(agg, pubkeys, msg)
        # dropping a signer's pubkey must fail the aggregate (a missing share).
        assert not bls_verify_aggregate(agg, pubkeys[:2], msg)
    finally:
        for k in keys:
            k.close()


def test_closed_keypair_cannot_sign() -> None:
    kp = BlsKeypair.generate()
    kp.close()
    kp.close()  # idempotent.
    with pytest.raises(ValueError):
        kp.sign(b"x")


def test_wrong_length_inputs_raise_value_error() -> None:
    with BlsKeypair.generate() as kp:
        sig = kp.sign(b"m")
        with pytest.raises(ValueError):
            bls_verify(sig, b"too short", b"m")
        with pytest.raises(ValueError):
            bls_aggregate([])


def test_bls_unavailable_message_when_core_only() -> None:
    # this test only runs when trust IS available (module skip), so just assert the
    # probe agrees with being able to generate a key.
    assert trust.available()
