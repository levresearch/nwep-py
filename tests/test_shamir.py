"""shamir secret-sharing tests NW150400: split + combine threshold recovery."""

from __future__ import annotations

import pytest

import nwep
from nwep import shamir

SECRET = bytes(range(32))  # a 32-byte recovery key, the intended use.


def test_split_produces_n_shares_of_the_right_size() -> None:
    shares = shamir.split(SECRET, threshold=3, shares=5)
    assert len(shares) == 5
    assert all(len(s) == 1 + len(SECRET) for s in shares)  # index byte + data.
    # shares are distinct (distinct index bytes).
    assert len({s[0] for s in shares}) == 5


def test_threshold_shares_reconstruct_the_secret() -> None:
    shares = shamir.split(SECRET, threshold=3, shares=5)
    # any 3 of the 5 reconstruct it.
    assert shamir.combine(shares[:3]) == SECRET
    assert shamir.combine([shares[0], shares[2], shares[4]]) == SECRET
    assert shamir.combine(shares) == SECRET  # all of them too.


def test_fewer_than_threshold_does_not_reconstruct() -> None:
    shares = shamir.split(SECRET, threshold=3, shares=5)
    # 2 shares are below the threshold: the result is not the secret (and the
    # library may also reject it). either way it must not equal the secret.
    try:
        wrong = shamir.combine(shares[:2])
    except nwep.NwepError:
        return
    assert wrong != SECRET


def test_duplicate_shares_are_rejected() -> None:
    shares = shamir.split(SECRET, threshold=2, shares=3)
    with pytest.raises(nwep.ConfigError):
        shamir.combine([shares[0], shares[0]])  # duplicate index.


def test_split_rejects_empty_secret() -> None:
    with pytest.raises(ValueError):
        shamir.split(b"", 2, 3)


def test_combine_rejects_mismatched_lengths() -> None:
    shares = shamir.split(SECRET, 2, 3)
    with pytest.raises(ValueError):
        shamir.combine([shares[0], shares[1][:-1]])
