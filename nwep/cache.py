"""cache is the response cache, per-client and shared signed NW060700 NW060900.

a Cache stores responses bounded by total bytes and entry count. attached to a
client (Client.set_cache) it transparently serves repeat reads. as a shared cache
it stores "public", signed responses a proxy received from origins and serves them
to other clients, who trust them via the response signature against the origin
node, not the connection  -  the put_signed / get_signed surface. core library, no
trust dependency.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional, Union

from . import _sys
from .errors import check
from .wire import Method

if TYPE_CHECKING:
    from .client import Response

ffi = _sys.ffi
lib = _sys.lib

# get_signed return codes that mean "cannot serve from cache", treated as a miss.
_APP_NOT_FOUND = -601
_CRYPTO_VERIFY = -304
_PUBKEY = _sys.PUBKEY_SIZE


@dataclass(frozen=True, slots=True)
class CacheStats:
    """CacheStats is a snapshot of a cache's counters NW060700."""

    hits: int
    misses: int
    stores: int
    evictions: int


class Cache:
    """Cache stores responses, per-client or shared between clients NW060700 NW060900.

    create one bounded by bytes and entries. attach it to a client with
    Client.set_cache to serve repeat reads, or use put_signed / get_signed as a
    shared proxy cache. it owns c memory; use it as a context manager, and detach
    it from any client (or close the client) before closing it.
    """

    __slots__ = ("_handle", "_closed")

    def __init__(self, max_bytes: int, max_entries: int):
        """creates a cache bounded by total stored bytes and entry count NW060700.

        raises InternalError on allocation failure.
        """
        handle = lib.nwep_cache_create(max_bytes, max_entries)
        if handle == ffi.NULL:
            from .errors import InternalError

            raise InternalError("cache allocation failed")
        self._handle = handle
        self._closed = False

    def put_signed(
        self,
        method: Union[Method, str],
        path: str,
        response: "Response",
        origin_pubkey: bytes,
        now_secs: int,
    ) -> None:
        """stores a public, signed response for sharing to other clients NW060900.

        verifies the response against origin_pubkey for path before storing. the
        proxy surface: a proxy stores what it fetched from an origin so it can
        serve it to others who trust the signature, not the connection.

        raises ProtocolError when the response is not `public` or unsigned,
        CryptoError on a bad signature, ValueError on a wrong-length key.
        """
        self._check_open()
        _expect(origin_pubkey, _PUBKEY, "origin_pubkey")
        check(
            lib.nwep_cache_put_signed(
                self._handle,
                str(method).encode("utf-8"),
                path.encode("utf-8"),
                response._raw_message(),
                origin_pubkey,
                now_secs,
            )
        )

    def get_signed(
        self,
        method: Union[Method, str],
        path: str,
        origin_pubkey: bytes,
        now_secs: int,
    ) -> Optional["Response"]:
        """looks up a shared entry, re-verifying it against the origin NW060900.

        re-checks the stored response's signature and freshness against
        origin_pubkey at now_secs before serving it.

        returns the Response on a hit, or None when there is no usable entry (a
        genuine miss, or one that no longer verifies or has gone stale).
        raises ValueError on a wrong-length key.
        """
        self._check_open()
        _expect(origin_pubkey, _PUBKEY, "origin_pubkey")
        out = ffi.new("nwep_message **")
        rc = lib.nwep_cache_get_signed(
            self._handle,
            str(method).encode("utf-8"),
            path.encode("utf-8"),
            origin_pubkey,
            now_secs,
            out,
        )
        if rc == 0:
            from .client import Response

            return Response(out[0])
        if rc in (_APP_NOT_FOUND, _CRYPTO_VERIFY):
            return None
        check(rc)
        return None

    def stats(self) -> CacheStats:
        """returns a snapshot of the cache's hit/miss/store/eviction counters NW060700."""
        self._check_open()
        hits = ffi.new("uint64_t *")
        misses = ffi.new("uint64_t *")
        stores = ffi.new("uint64_t *")
        evictions = ffi.new("uint64_t *")
        lib.nwep_cache_stats(self._handle, hits, misses, stores, evictions)
        return CacheStats(
            int(hits[0]), int(misses[0]), int(stores[0]), int(evictions[0])
        )

    def clear(self) -> None:
        """drops all stored entries; the cache stays usable NW060700."""
        self._check_open()
        lib.nwep_cache_clear(self._handle)

    @property
    def raw(self) -> "_sys.CData":
        """returns the raw c nwep_cache pointer, the escape hatch to sys NWG0200."""
        return self._handle

    def close(self) -> None:
        """frees the cache. idempotent; detach it from any client first."""
        if not self._closed:
            lib.nwep_cache_free(self._handle)
            self._closed = True

    def _check_open(self) -> None:
        if self._closed:
            raise ValueError("cache is closed")

    def __enter__(self) -> "Cache":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def __repr__(self) -> str:
        return "Cache(closed)" if self._closed else "Cache(open)"


def _expect(buf: bytes, size: int, name: str) -> None:
    """raises ValueError when a byte argument is not the exact expected length."""
    if len(buf) != size:
        raise ValueError(f"{name} must be {size} bytes, got {len(buf)}")
