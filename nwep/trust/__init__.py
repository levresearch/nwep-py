"""trust is the bls threshold + merkle-anchor layer of the protocol NW120000.

this subpackage wraps the trust half of libnwep  -  the bls12-381 threshold
signatures, the merkle checkpoint, the trust store, and the quorum anchor. those
symbols live only in the full libnwep.so (built with blst), which is the artifact
the bindings ship, so the trust layer is available by default. it is absent only
when NWEP_LIB=core opted into the lean, trust-less libnwep_core.so build.

    import nwep.trust as trust
    if trust.available():
        with trust.BlsKeypair.generate() as kp:
            sig = kp.sign(b"epoch root")
            assert trust.bls_verify(sig, kp.public_key, b"epoch root")
"""

from __future__ import annotations

from .. import _sys
from .bls import (
    BlsKeypair,
    bls_aggregate,
    bls_verify,
    bls_verify_aggregate,
)
from .anchor import (
    AnchorNode,
    PartialSig,
    finish_checkpoint,
    request_partial_sig,
)
from .checkpoint import Checkpoint, CheckpointStatus, genesis_checkpoint
from .store import (
    KeyRotationVerdict,
    KeyStatus,
    TrustStore,
    evaluate_key_rotation,
)


def available() -> bool:
    """returns whether the loaded library includes the trust layer NW120000.

    True by default (the bindings ship the full libnwep.so); False only when
    NWEP_LIB=core opted into the trust-less libnwep_core.so. every trust call
    raises a clear error when it is absent.
    """
    return _sys.trust_available()


def version() -> str:
    """returns the trust build's version string NW120000.

    raises RuntimeError when the loaded library lacks the trust layer.
    """
    from .bls import _require_trust

    _require_trust()
    return _sys.ffi.string(_sys.lib.nwep_trust_version()).decode("ascii")


__all__ = [
    "available",
    "version",
    "BlsKeypair",
    "bls_verify",
    "bls_aggregate",
    "bls_verify_aggregate",
    "Checkpoint",
    "CheckpointStatus",
    "genesis_checkpoint",
    "TrustStore",
    "KeyStatus",
    "KeyRotationVerdict",
    "evaluate_key_rotation",
    "AnchorNode",
    "PartialSig",
    "request_partial_sig",
    "finish_checkpoint",
]
