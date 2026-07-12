"""wire holds the request verb and response status tokens NW050000 NW080000.

Method is the verb a request carries (read, write, update, delete, ...). Status
is the result token a response carries (ok, not-found, rate-limited, ...). both
are plain integers on the wire, so both are IntEnum: a member passes straight to
the c abi as its code, str(member) is the lowercase protocol token, and Status(7)
or Method(0) reconstructs one from a code.
"""

from __future__ import annotations

from enum import IntEnum

from . import _sys

ffi = _sys.ffi
lib = _sys.lib


def _method_token(code: int) -> str:
    ptr = lib.nwep_method_str(code)
    return ffi.string(ptr).decode("ascii") if ptr != ffi.NULL else f"method-{code}"


def _status_token(code: int) -> str:
    ptr = lib.nwep_status_str(code)
    return ffi.string(ptr).decode("ascii") if ptr != ffi.NULL else f"status-{code}"


class Compression(IntEnum):
    """Compression is the body codec negotiated on a connection NW000017.

    NONE when no compression was negotiated, ZSTD for zstd, UNKNOWN (-1) for an
    unknown connection or a handle not yet connected.
    """

    NONE = 0
    ZSTD = 1
    UNKNOWN = -1


class Method(IntEnum):
    """Method is the verb a request carries NW050000.

    the public verbs a caller sends. connect and authenticate (codes 4 and 5) are
    internal handshake methods the library drives itself, so they are not members
    here. str(Method.READ) is its lowercase token, "read".
    """

    READ = 0
    WRITE = 1
    UPDATE = 2
    DELETE = 3
    HEARTBEAT = 6
    HEAD = 7

    @property
    def token(self) -> str:
        """returns the lowercase protocol token of this method NW050000."""
        return _method_token(self.value)

    def __str__(self) -> str:
        return self.token


class Status(IntEnum):
    """Status is the result token a response carries NW080000.

    str(Status.NOT_FOUND) is its lowercase token, "not-found". construct from a
    code with Status(code), or read the token of any code with Status.token_of.
    """

    OK = 0
    CREATED = 1
    ACCEPTED = 2
    NO_CONTENT = 3
    PARTIAL_CONTENT = 4
    MOVED = 5
    NOT_MODIFIED = 6
    BAD_REQUEST = 7
    UNAUTHORIZED = 8
    FORBIDDEN = 9
    NOT_FOUND = 10
    NOT_ALLOWED = 11
    CONFLICT = 12
    GONE = 13
    TOO_LARGE = 14
    PRECONDITION_FAILED = 15
    RANGE_NOT_SATISFIABLE = 16
    RATE_LIMITED = 17
    ERROR = 18
    UNAVAILABLE = 19
    TIMEOUT = 20
    NOT_IMPLEMENTED = 21

    @property
    def token(self) -> str:
        """returns the lowercase protocol token of this status NW080000."""
        return _status_token(self.value)

    def __str__(self) -> str:
        return self.token
