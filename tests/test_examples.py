"""runs each example program as a subprocess and asserts it exits cleanly (D9).

this is the discipline the guide ties the examples to: "the binding works" means
"it reproduced the dogfood apps". each example mirrors a sandbox app and is a
self-contained program; here we run them all and require a zero exit, so an example
that rots is a failing test.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

_EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
_NAMES = [
    "identity",
    "managed",
    "managed_dht",
    "managed_stream",
    "nwkv",
    "nwserve",
    "nwlog",
    "nwcurl",
    "nwproxy",
    "nwdrop",
]


@pytest.mark.parametrize("name", _NAMES)
def test_example_runs_cleanly(name: str) -> None:
    env = dict(os.environ)
    # the examples import _common from their own directory.
    env["PYTHONPATH"] = os.pathsep.join(
        [str(_EXAMPLES), str(_EXAMPLES.parent), env.get("PYTHONPATH", "")]
    )
    result = subprocess.run(
        [sys.executable, str(_EXAMPLES / f"{name}.py")],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, f"{name} failed:\n{result.stdout}\n{result.stderr}"
    assert result.stdout.strip(), f"{name} produced no output"
