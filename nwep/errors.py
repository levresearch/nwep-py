"""errors is the python face of the NW130000 error table NWG0800.

every error code the c abi can return becomes an exception, grouped into the
spec's families by inheritance so a caller catches at whatever granularity it
wants. `except nwep.AppError` catches every -6xx, `except nwep.RateLimited`
catches only -603, and `except nwep.FatalError` catches every connection-killing
code across all families. each instance keeps the numeric `code` and the spec
`name`, and its message is the same text the c library gives via nwep_strerror.

the leaf classes are generated from the spec table at import, since one
hand-written stub per code would be noise, not craft. the families and the
factory below are the documented surface.
"""

from __future__ import annotations

from . import _sys


class NwepError(Exception):
    """NwepError is the base of every error the protocol raises NW130000.

    carries the numeric `code`, the spec `name` (its kebab-case token), and
    `fatal` (whether the spec marks it connection-killing, NW130100). catch this
    to handle any protocol failure; catch a family or leaf subclass to narrow.
    """

    code: int = 0
    name: str = "ok"
    fatal: bool = False

    def __init__(self, message: str | None = None):
        super().__init__(message or strerror(self.code))


class FatalError(NwepError):
    """FatalError marks a connection-killing error NW130100.

    a fatal error requires immediate, silent connection teardown with no error
    response sent to the peer NW090900. every fatal leaf also subclasses its own
    family, so `except CryptoError` still catches a crypto-fatal code.
    """


class ConfigError(NwepError):
    """ConfigError is a configuration fault, the -1xx family NW130000."""


class NetworkError(NwepError):
    """NetworkError is a transport or quic fault, the -2xx family NW130000."""


class CryptoError(NwepError):
    """CryptoError is a cryptographic fault, the -3xx family NW130000."""


class ProtocolError(NwepError):
    """ProtocolError is a malformed or out-of-order message, the -4xx family NW130000."""


class IdentityError(NwepError):
    """IdentityError is an identity or key fault, the -5xx family NW130000."""


class AppError(NwepError):
    """AppError is an application-level result a peer reports, the -6xx family NW130000."""


class TrustError(NwepError):
    """TrustError is a trust-layer fault, the -7xx family NW130000."""


class InternalError(NwepError):
    """InternalError is a library-internal fault, the -8xx family NW130000."""


def strerror(code: int) -> str:
    """returns the library's human message for an error code NW130000.

    relies on the c nwep_strerror table, so the text matches every other binding.
    returns the message string, or a generic fallback for an unknown code.
    """
    ptr = _sys.lib.nwep_strerror(code)
    if ptr == _sys.ffi.NULL:
        return f"unknown error ({code})"
    return _sys.ffi.string(ptr).decode("utf-8", "replace")


# the NW130000 table: (code, ClassName, kebab-name, family, fatal). the single
# source for the generated leaf classes and the code -> class lookup. when the
# spec adds a code it gets one row here.
_TABLE: list[tuple[int, str, str, type[NwepError], bool]] = [
    (-101, "ConfigInvalid", "config-invalid", ConfigError, False),
    (-102, "ConfigMissing", "config-missing", ConfigError, False),
    (-201, "NetworkConnect", "network-connect", NetworkError, False),
    (-202, "NetworkTimeout", "network-timeout", NetworkError, False),
    (-203, "NetworkClosed", "network-closed", NetworkError, False),
    (-204, "NetworkQuic", "network-quic", NetworkError, False),
    (-205, "NetworkTls", "network-tls", NetworkError, False),
    (-301, "CryptoKeygen", "crypto-keygen", CryptoError, False),
    (-302, "CryptoRand", "crypto-rand", CryptoError, False),
    (-303, "CryptoSign", "crypto-sign", CryptoError, False),
    (-304, "CryptoVerify", "crypto-verify", CryptoError, False),
    (-381, "CryptoFatalCert", "crypto-fatal-cert", CryptoError, True),
    (
        -382,
        "CryptoFatalNodeidMismatch",
        "crypto-fatal-nodeid-mismatch",
        CryptoError,
        True,
    ),
    (-383, "CryptoFatalChallenge", "crypto-fatal-challenge", CryptoError, True),
    (-384, "CryptoFatalServerSig", "crypto-fatal-server-sig", CryptoError, True),
    (-385, "CryptoFatalClientSig", "crypto-fatal-client-sig", CryptoError, True),
    (-401, "ProtoInvalidMessage", "proto-invalid-message", ProtocolError, False),
    (-402, "ProtoInvalidMethod", "proto-invalid-method", ProtocolError, False),
    (-403, "ProtoInvalidHeader", "proto-invalid-header", ProtocolError, False),
    (-404, "ProtoConnectRequired", "proto-connect-required", ProtocolError, False),
    (-405, "ProtoStreamReuse", "proto-stream-reuse", ProtocolError, False),
    (-406, "ProtoMaxStreams", "proto-max-streams", ProtocolError, False),
    (-407, "ProtoFlowControl", "proto-flow-control", ProtocolError, False),
    (-408, "ProtoMessageTooLarge", "proto-message-too-large", ProtocolError, False),
    (-481, "ProtoFatalVersion", "proto-fatal-version", ProtocolError, True),
    (-501, "IdentityGenerate", "identity-generate", IdentityError, False),
    (-502, "IdentityMismatch", "identity-mismatch", IdentityError, False),
    (-503, "IdentityNotFound", "identity-not-found", IdentityError, False),
    (-504, "IdentityRevoked", "identity-revoked", IdentityError, False),
    (-601, "AppNotFound", "app-not-found", AppError, False),
    (-602, "AppConflict", "app-conflict", AppError, False),
    (-603, "RateLimited", "app-rate-limited", AppError, False),
    (-604, "Forbidden", "app-forbidden", AppError, False),
    (-701, "TrustInvalidEntry", "trust-invalid-entry", TrustError, False),
    (-702, "TrustInvalidAnchor", "trust-invalid-anchor", TrustError, False),
    (-703, "TrustStaleCheckpoint", "trust-stale-checkpoint", TrustError, False),
    (-704, "TrustThreshold", "trust-threshold", TrustError, False),
    (-705, "TrustRevoked", "trust-revoked", TrustError, False),
    (-706, "TrustNoCheckpoint", "trust-no-checkpoint", TrustError, False),
    (-781, "TrustFatalEquivocation", "trust-fatal-equivocation", TrustError, True),
    (-782, "TrustFatalLogCorrupt", "trust-fatal-log-corrupt", TrustError, True),
    (-801, "Internal", "internal", InternalError, False),
    (-802, "InternalAlloc", "internal-alloc", InternalError, False),
]

# code -> exception class, built as the table is realized into classes below.
_BY_CODE: dict[int, type[NwepError]] = {}
__all__ = [
    "NwepError",
    "FatalError",
    "ConfigError",
    "NetworkError",
    "CryptoError",
    "ProtocolError",
    "IdentityError",
    "AppError",
    "TrustError",
    "InternalError",
    "WouldBlock",
    "strerror",
    "check",
    "from_code",
]

_globals = globals()
for _code, _cls_name, _kebab, _family, _fatal in _TABLE:
    # a fatal leaf inherits both its family and the FatalError marker, so either
    # axis catches it. the spec name and code live as class attributes.
    _bases = (_family, FatalError) if _fatal else (_family,)
    _leaf = type(_cls_name, _bases, {"code": _code, "name": _kebab, "fatal": _fatal})
    _leaf.__doc__ = f"{_kebab} ({_code}). see NW130000."
    _leaf.__module__ = __name__
    _globals[_cls_name] = _leaf
    _BY_CODE[_code] = _leaf
    __all__.append(_cls_name)


class WouldBlock(NwepError):
    """WouldBlock means an async operation is not ready yet, not a failure (-803).

    the safe layer raises it where the spec's WOULD_BLOCK code means "poll again
    later" (an async submit or stream read with nothing available). a managed
    runtime handles it internally; a driven caller retries on the next tick.
    """

    code = -803
    name = "would-block"
    fatal = False


_BY_CODE[-803] = WouldBlock


def from_code(code: int) -> NwepError:
    """builds the exception instance for a c return code NW130000.

    relies on the NW130000 code table. returns the matching leaf exception, or a
    bare NwepError carrying the code when a newer library returns one this build
    does not yet name.
    """
    cls = _BY_CODE.get(code)
    if cls is None:
        err = NwepError(strerror(code))
        err.code = code
        err.name = f"unknown-{code}"
        return err
    return cls()


def check(code: int) -> int:
    """raises the matching exception when a c return code is an error NW130000.

    a non-negative code is success and is returned unchanged (some calls return a
    count); a negative code raises. this is the one gate every wrapper passes c
    return codes through.

    returns the code unchanged when it is not an error.
    raises the NW130000 exception for the code otherwise.
    """
    if code < 0:
        raise from_code(code)
    return code
