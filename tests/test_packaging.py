"""packaging guard: the bindings ship the full libnwep (trust) by default.

the language bindings are packaged with libnwep (the trust build, with the bls
anchor layer), not the lean libnwep_core  -  so the trust layer must be present in a
default load. this test fails if a packaging regression bundles core instead, or if
the loader stops preferring the full build. it is the one place that asserts the
shipping contract, so the trust-gated suites actually run by default rather than
silently skipping.

run with NWEP_LIB=core to test the opt-in lean build, where this test instead
asserts the trust layer is correctly absent.
"""

from __future__ import annotations

import os

import nwep
import nwep._sys as _sys
import nwep.trust as trust

_FORCED_CORE = os.environ.get("NWEP_LIB", "").lower() in (
    "core",
    "core_only",
    "nwep_core",
)


def test_shipped_default_loads_the_trust_build() -> None:
    if _FORCED_CORE:
        # the opt-in lean path: trust must be cleanly absent, not crash.
        assert not trust.available()
        return
    # the default, shipped path: the trust layer must be present and usable.
    assert trust.available(), (
        "the default load did not include the trust layer  -  the bindings ship "
        "libnwep (the trust build), so a default `import nwep` must expose it. a "
        "packaging regression may have bundled libnwep_core instead."
    )
    # and it must actually work, not just be declared.
    version = trust.version()
    assert isinstance(version, str) and version
    with trust.BlsKeypair.generate() as keypair:
        signature = keypair.sign(b"packaging guard")
        assert trust.bls_verify(signature, keypair.public_key, b"packaging guard")


def test_library_version_is_readable() -> None:
    # the core version string is always available, on either build.
    assert isinstance(nwep.version(), str) and nwep.version()


# cross-platform loader NWG1200.
# the binding dlopens the native lib by name, and the name differs per os. a
# loader that hardcodes `.so` only works on linux; these lock the per-platform
# resolution so a regression to a single-os loader is caught without that os.


def test_lib_names_are_platform_correct(monkeypatch) -> None:
    cases = {
        "win32": ("nwep.dll", "nwep_core.dll"),  # no `lib` prefix, .dll
        "darwin": ("libnwep.dylib", "libnwep_core.dylib"),
        "linux": ("libnwep.so", "libnwep_core.so"),
        "android": ("libnwep.so", "libnwep_core.so"),  # bionic is an elf platform
    }
    for platform, (full_first, core_first) in cases.items():
        monkeypatch.setattr(_sys.sys, "platform", platform)
        # default prefers the full build; the per-os name + ordering must hold.
        assert _sys._lib_names(prefer_core=False)[0] == full_first, platform
        assert _sys._lib_names(prefer_core=True)[0] == core_first, platform


def test_candidate_dirs_cover_per_os_install_layout() -> None:
    dirs = [str(d) for d in _sys._candidate_dirs()]
    # windows installs the dll under bin/, unix the .so/.dylib under lib/  -  both
    # must be searched, plus the package dir + _libs/ where a wheel bundles it.
    assert any(d.endswith(os.sep + "bin") or d.endswith("/bin") for d in dirs)
    assert any(d.endswith(os.sep + "lib") or d.endswith("/lib") for d in dirs)
    assert any(d.endswith(os.sep + "nwep") or d.endswith("/nwep") for d in dirs)
    assert any("_libs" in d for d in dirs)
