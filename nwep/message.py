"""message holds the shared readers over a decoded nwep_message NW060000.

a request and a response are both nwep_message under the hood, so the header,
body, and status accessors live here once and Request (server side) and Response
(client side) both read through them. every returned value is an owned python
object, so it outlives the borrowed c message.
"""

from __future__ import annotations

from typing import Iterator, Mapping, Optional, Sequence, Union

from . import _sys

ffi = _sys.ffi
lib = _sys.lib

HeadersArg = Union[Mapping[str, str], Sequence[tuple[str, str]]]


def encode_headers(headers: Optional[HeadersArg]) -> tuple["_sys.CData", list]:
    """encodes request/response headers as a NULL-terminated nwep_header array NW060300.

    returns (array_or_NULL, keepalive). the keepalive list owns the backing c
    strings, which must stay referenced for as long as the array is used by the
    call.
    """
    if not headers:
        return ffi.NULL, []
    items = list(headers.items()) if isinstance(headers, Mapping) else list(headers)
    array = ffi.new("nwep_header[]", len(items) + 1)  # +1 NULL sentinel, zeroed.
    keep: list = []
    for i, (name, value) in enumerate(items):
        cname = ffi.new("char[]", name.encode("utf-8"))
        cvalue = ffi.new("char[]", value.encode("utf-8"))
        keep.append(cname)
        keep.append(cvalue)
        array[i].name = cname
        array[i].value = cvalue
    return array, keep


def header(msg: "_sys.CData", name: str) -> Optional[str]:
    """returns the value of a header, or None when it is absent NW060300."""
    ptr = lib.nwep_message_get_header(msg, name.encode("utf-8"))
    return ffi.string(ptr).decode("utf-8") if ptr != ffi.NULL else None


def headers(msg: "_sys.CData") -> Iterator[tuple[str, str]]:
    """iterates every header in wire order NW060300."""
    name = ffi.new("const char **")
    value = ffi.new("const char **")
    index = 0
    while lib.nwep_message_header_at(msg, index, name, value) == 0:
        yield (
            ffi.string(name[0]).decode("utf-8"),
            ffi.string(value[0]).decode("utf-8"),
        )
        index += 1


def body(msg: "_sys.CData") -> bytes:
    """returns the message body, empty when there is none NW060000."""
    out_len = ffi.new("size_t *")
    ptr = lib.nwep_message_get_body(msg, out_len)
    if ptr == ffi.NULL or out_len[0] == 0:
        return b""
    return bytes(ffi.buffer(ptr, out_len[0]))


def header_count(msg: "_sys.CData") -> int:
    """returns the number of headers on a message NW060300."""
    return int(lib.nwep_message_header_count(msg))


def status_token(msg: "_sys.CData") -> Optional[str]:
    """returns the response status token, or None on a request NW080000."""
    ptr = lib.nwep_message_get_status(msg)
    return ffi.string(ptr).decode("utf-8") if ptr != ffi.NULL else None
