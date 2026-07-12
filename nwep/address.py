"""address is the transport address a server binds and a client dials NW110300.

Address wraps the protocol's opaque ipv6 socket address (a sockaddr_in6 the
library treats as 32 bytes). it is built through the factory constructors rather
than by hand, since the byte layout is the library's to own, and it carries a
port. ipv4 peers are reached through the ::ffff:a.b.c.d mapped form.
"""

from __future__ import annotations

from . import _sys

ffi = _sys.ffi
lib = _sys.lib

_ADDR_SIZE = 32
_IPV6_SIZE = 16


class Address:
    """Address is an opaque ipv6 socket address, a bind or dial target NW110300.

    construct one with loopback(), wildcard(), ipv4_mapped(), or from_bytes(); the
    raw layout belongs to the library. equal addresses compare and hash by their
    bytes, and .port reads the port back.
    """

    __slots__ = ("_addr",)

    def __init__(self, _addr: "_sys.CData"):
        """wraps a populated c nwep_address. use the factory constructors instead."""
        self._addr = _addr

    @classmethod
    def loopback(cls, port: int) -> "Address":
        """builds the ::1 loopback address at the given port NW110300."""
        out = ffi.new("nwep_address *")
        lib.nwep_address_loopback(out, port)
        return cls(out)

    @classmethod
    def wildcard(cls, port: int) -> "Address":
        """builds the :: wildcard address (all interfaces) at the given port NW110300."""
        out = ffi.new("nwep_address *")
        lib.nwep_address_wildcard(out, port)
        return cls(out)

    @classmethod
    def ipv4_mapped(cls, a: int, b: int, c: int, d: int, port: int) -> "Address":
        """builds the ::ffff:a.b.c.d ipv4-mapped address at the given port NW110300.

        the way to reach an ipv4 peer, and the way to give loopback nodes distinct
        source ips (127.0.0.x) when the dht rate-limits per source ip.
        """
        out = ffi.new("nwep_address *")
        lib.nwep_address_ipv4_mapped(out, a, b, c, d, port)
        return cls(out)

    @classmethod
    def from_bytes(cls, addr: bytes, port: int) -> "Address":
        """builds an address from a 16-byte raw ipv6 address (network order) + port.

        returns the Address.
        raises ValueError when addr is not exactly 16 bytes.
        """
        if len(addr) != _IPV6_SIZE:
            raise ValueError(
                f"ipv6 address must be {_IPV6_SIZE} bytes, got {len(addr)}"
            )
        out = ffi.new("nwep_address *")
        lib.nwep_address_from_bytes(out, addr, port)
        return cls(out)

    @property
    def port(self) -> int:
        """returns the host-order port of this address NW110300."""
        return lib.nwep_address_get_port(self._addr)

    def _raw(self) -> "_sys.CData":
        """borrows the raw c nwep_address pointer, for handing to a lower layer."""
        return self._addr

    def __bytes__(self) -> bytes:
        return bytes(ffi.buffer(self._addr, _ADDR_SIZE))

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Address) and bytes(other) == bytes(self)

    def __hash__(self) -> int:
        return hash(bytes(self))

    def __repr__(self) -> str:
        return f"Address(port={self.port})"
