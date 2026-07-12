"""nwep is the idiomatic python binding for the web/1 protocol over quic.

this package is the safe, native face of libnwep. the raw cffi declarations
live one layer down in nwep._sys, reachable for anything this layer does not
yet wrap (no cliffs, NWG0200).

today the package covers the identity layer NW040200. the server, client, dht,
and trust layers are added slice by slice.

    >>> import nwep
    >>> with nwep.Identity.generate() as identity:
    ...     identity.node_id.verify(identity.public_key)
    True
"""

from __future__ import annotations

from . import errors as errors
from . import shamir as shamir
from ._sys import ffi as _ffi
from ._sys import lib as _lib
from .errors import (
    AppError,
    ConfigError,
    CryptoError,
    FatalError,
    IdentityError,
    InternalError,
    NetworkError,
    NwepError,
    ProtocolError,
    TrustError,
    WouldBlock,
)
from ._sys import DEFAULT_PORT
from .address import Address
from .cache import Cache, CacheStats
from .client import (
    Client,
    ClientBuilder,
    ClientMetrics,
    Connecting,
    RequestId,
    Response,
    Stream,
    verify_response,
)
from .dht import Bootstrap, Dht, DhtMetrics, Record
from .identity import Identity, NodeId, verify_signature
from .log import (
    EntryType,
    KeyBinding,
    KeyRotation,
    Log,
    LogServer,
    Revocation,
    RevocationReason,
    entry_type,
)
from .runtime import AsyncClient, AsyncStream, RunningServer
from .server import (
    ByteRange,
    RangeKind,
    RangeOutcome,
    Reply,
    Request,
    Responder,
    Server,
    ServerBuilder,
    ServerMetrics,
    cid_shard_id,
    reuse_port_supported,
)
from .uri import Uri
from .wire import Compression, Method, Status

__all__ = [
    "Identity",
    "NodeId",
    "verify_signature",
    "Address",
    "Uri",
    "Method",
    "Status",
    "Compression",
    "Server",
    "ServerBuilder",
    "ServerMetrics",
    "Request",
    "Responder",
    "Reply",
    "ByteRange",
    "RangeKind",
    "RangeOutcome",
    "reuse_port_supported",
    "cid_shard_id",
    "Client",
    "ClientBuilder",
    "ClientMetrics",
    "Connecting",
    "RequestId",
    "Response",
    "Stream",
    "verify_response",
    "Cache",
    "CacheStats",
    "Bootstrap",
    "Dht",
    "Record",
    "DhtMetrics",
    "RunningServer",
    "AsyncClient",
    "AsyncStream",
    "Log",
    "LogServer",
    "EntryType",
    "RevocationReason",
    "KeyBinding",
    "KeyRotation",
    "Revocation",
    "entry_type",
    "DEFAULT_PORT",
    "version",
    # the error taxonomy NWG0800; every leaf also lives on nwep.errors.
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
]


def version() -> str:
    """returns the version string of the linked nwep library.

    the library returns a static nul-terminated ascii string, never null.
    """
    return _ffi.string(_lib.nwep_version()).decode("ascii")
