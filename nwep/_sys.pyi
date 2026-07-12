"""Type stub for _sys — gives pyright/pylance a typed surface for the cffi layer.

The cffi lib and ffi objects are dynamically typed; pyright cannot resolve
attributes on them from _CDEF at analysis time. _Lib and _Ffi expose
__getattr__ -> Any so every call like lib.nwep_strerror(...) or ffi.new(...)
is treated as Any. Everything else in the package still gets full checking.
"""

from typing import Any, TypeAlias

CData: TypeAlias = Any

NODEID_SIZE: int
PUBKEY_SIZE: int
PRIVKEY_SIZE: int
SIG_SIZE: int
BLS_PUBKEY_SIZE: int
BLS_SECKEY_SIZE: int
BLS_SIGNATURE_SIZE: int
DEFAULT_PORT: int

class _Lib:
    def __getattr__(self, name: str) -> Any: ...

class _Ffi:
    NULL: Any
    def __getattr__(self, name: str) -> Any: ...

lib: _Lib
ffi: _Ffi

def trust_available() -> bool: ...
