"""shamir is threshold secret sharing, split and combine NW150400.

split a secret (its intended use is the offline recovery private key) into n
shares so that any t of them reconstruct it and t-1 reveal nothing. each share is
1 + len(secret) bytes: a 1-based index byte followed by the share data. shares and
reconstructed secrets are key material; zeroize them when done (the returned bytes
are immutable, so overwrite or drop references promptly). core library.
"""

from __future__ import annotations

from typing import Sequence

from . import _sys
from .errors import check

ffi = _sys.ffi
lib = _sys.lib


def split(secret: bytes, threshold: int, shares: int) -> list[bytes]:
    """splits a secret into shares, any threshold of which reconstruct it NW150400.

    requires 2 <= threshold <= shares <= 255. each returned share is
    1 + len(secret) bytes (a 1-based index byte + data). knowing fewer than
    threshold shares reveals nothing about the secret.

    returns the list of shares.
    raises ConfigError for an out-of-range threshold or count, ValueError on an
    empty secret.
    """
    if not secret:
        raise ValueError("cannot split an empty secret")
    share_len = 1 + len(secret)
    total = shares * share_len
    out = ffi.new("uint8_t[]", total)
    outlen = ffi.new("size_t *", total)
    check(lib.nwep_shamir_split(secret, len(secret), threshold, shares, out, outlen))
    blob = bytes(ffi.buffer(out, outlen[0]))
    return [blob[i * share_len : (i + 1) * share_len] for i in range(shares)]


def combine(shares: Sequence[bytes]) -> bytes:
    """reconstructs a secret from a set of shares NW150400.

    each share must be the same length (1 + secret length) and carry a distinct
    index byte; at least `threshold` of the original shares are required for a
    correct result.

    returns the reconstructed secret bytes.
    raises ConfigError for duplicate indices or a length mismatch, ValueError when
    no shares are given or they differ in length.
    """
    if not shares:
        raise ValueError("combine needs at least one share")
    share_len = len(shares[0])
    if any(len(s) != share_len for s in shares):
        raise ValueError("all shares must be the same length")
    blob = b"".join(shares)
    out = ffi.new("uint8_t[]", share_len)  # secret is share_len - 1 bytes.
    outlen = ffi.new("size_t *", share_len)
    check(lib.nwep_shamir_combine(blob, len(shares), share_len, out, outlen))
    return bytes(ffi.buffer(out, outlen[0]))
