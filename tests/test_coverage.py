"""coverage anchor for the sys layer NWG1000.

symbols.txt is the authoritative export set of libnwep_core + libnwep, checked in
and regenerated from the built .so files (see the header of symbols.txt). this
test diffs the function names declared in nwep._sys._CDEF against it.

it hard-fails on a phantom, a declared function that is not a real export, since
that is a typo or a symbol removed from the header and would be a load error at
first call. it reports forward progress as a count, because the sys layer is
filled in one slice at a time. when every symbol is declared the equality assert
turns the count into a totality guarantee.
"""

from __future__ import annotations

import re
from pathlib import Path

from nwep import _sys

_SYMBOLS_TXT = Path(__file__).resolve().parents[1] / "symbols.txt"

# a cffi function declaration is a `nwep_*` name immediately followed by `(`.
# typedef names (nwep_node_id;) and parameter types (nwep_node_id *p) are never
# followed by `(`, so this matches declared functions only.
_DECL = re.compile(r"\b(nwep_[a-z0-9_]+)\s*\(")


def authoritative() -> set[str]:
    lines = _SYMBOLS_TXT.read_text().splitlines()
    return {line.strip() for line in lines if line.strip() and not line.startswith("#")}


def declared() -> set[str]:
    # both the core cdef and the trust cdef (the full libnwep.so symbols).
    return set(_DECL.findall(_sys._CDEF)) | set(_DECL.findall(_sys._TRUST_CDEF))


def test_no_phantom_declarations() -> None:
    auth = authoritative()
    decl = declared()
    phantoms = decl - auth
    assert not phantoms, (
        f"_sys declares {sorted(phantoms)} which are not exported by the library "
        "(typo, or removed from the header). fix the cdef or symbols.txt."
    )
    print(f"nwep._sys coverage: {len(decl)} / {len(auth)} symbols declared")


def test_authoritative_set_is_the_expected_size() -> None:
    # guards symbols.txt against accidental truncation; 159 = 130 core + 29 trust.
    assert len(authoritative()) == 159
