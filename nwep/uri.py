"""uri is a parsed web:// address NW040400.

Uri is the result of parsing a "web://nodeid_base58[:port]/path" string. it holds
the node_id it names, an optional port (0 when absent), and the path. it is an
immutable value, the input to resolving and dialing a node by name.
"""

from __future__ import annotations

from . import _sys
from .errors import check
from .identity import NodeId

ffi = _sys.ffi
lib = _sys.lib


class Uri:
    """Uri is a parsed web:// address naming a node and a path NW040400.

    parse one with Uri.parse(). it exposes the node_id, the port (defaulted to
    DEFAULT_PORT when the uri omits it), and the path. str(uri) renders the
    canonical web:// form.
    """

    __slots__ = ("_node_id", "_port", "_path")

    def __init__(self, node_id: NodeId, port: int, path: str):
        """builds a uri from its parts. use Uri.parse() to parse a string."""
        self._node_id = node_id
        self._port = port
        self._path = path

    @classmethod
    def parse(cls, text: str) -> "Uri":
        """parses a "web://nodeid_base58[:port]/path" string NW040400.

        copies the path out of the parse buffer immediately, since the c parser
        returns it as a slice borrowed from the input.

        returns the parsed Uri.
        raises ProtocolError when text is not a well-formed web:// uri.
        """
        out = ffi.new("nwep_uri *")
        raw = text.encode("utf-8")
        check(lib.nwep_uri_parse(out, raw, len(raw)))
        node_id = NodeId(bytes(ffi.buffer(out.node_id.bytes, _sys.NODEID_SIZE)))
        path = (
            ffi.string(out.path, out.path_len).decode("utf-8")
            if out.path != ffi.NULL
            else ""
        )
        return cls(node_id, int(out.port), path)

    @property
    def node_id(self) -> NodeId:
        """returns the node_id this uri names NW040200."""
        return self._node_id

    @property
    def port(self) -> int:
        """returns the port, defaulted to DEFAULT_PORT when the uri omits it NW040400."""
        return self._port

    @property
    def path(self) -> str:
        """returns the request path NW040400."""
        return self._path

    def __str__(self) -> str:
        host = self._node_id.base58()
        authority = f"{host}:{self._port}" if self._port else host
        return f"web://{authority}{self._path}"

    def __repr__(self) -> str:
        return f"Uri({self})"

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, Uri)
            and other._node_id == self._node_id
            and other._port == self._port
            and other._path == self._path
        )

    def __hash__(self) -> int:
        return hash((self._node_id, self._port, self._path))
