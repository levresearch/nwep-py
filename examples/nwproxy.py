"""nwproxy, a caching reverse proxy (mirrors sandbox/004-nwproxy).

a frontend defers each request, fetches from an origin on its loop, relays the
origin response verbatim (preserving the origin's end-to-end signature, spec 6.9),
and caches public responses to serve later hits without re-contacting the origin.
origin, proxy, and client all run in one process.

    python examples/nwproxy.py
"""

from __future__ import annotations

import threading

from _common import DrivenServer, now_secs
from nwep import Address, Cache, Client, Identity, Method, Server

ORIGIN_BODY = b"the origin's signed, public page"


def main() -> None:
    # the origin: serves a public, signed page.
    origin_id = Identity.generate()
    origin_pubkey = origin_id.public_key
    origin_srv = (
        Server.builder()
        .identity(origin_id)
        .bind(Address.loopback(0))
        .on_request(
            lambda req, res: (
                res.header("cache-control", "public").ok(ORIGIN_BODY)
                if req.path == "/page"
                else res.not_found()
            )
        )
        .build()
    )

    with DrivenServer(origin_srv) as origin:
        # the proxy holds a connection to the origin and a shared cache.
        origin_client = (
            Client.builder()
            .identity(Identity.generate())
            .connect(origin.node_id, Address.loopback(origin.port))
        )
        cache = Cache(8 * 1024 * 1024, 256)

        parked: list[tuple[int, int]] = []
        lock = threading.Lock()

        def proxy_handler(req, res):
            with lock:
                parked.append((req.conn_id, req.stream_id))
            return res.defer()  # answered from the loop after the origin fetch.

        proxy_id = Identity.generate()
        proxy_srv = (
            Server.builder()
            .identity(proxy_id)
            .bind(Address.loopback(0))
            .on_request(proxy_handler)
            .build()
        )

        def serve_parked():
            with lock:
                jobs = list(parked)
                parked.clear()
            for conn, stream in jobs:
                # a cache hit serves without re-contacting the origin.
                hit = cache.get_signed(Method.READ, "/page", origin_pubkey, now_secs())
                if hit is not None:
                    with hit:
                        proxy_srv.relay(conn, stream, hit)
                    print("  proxy: served from cache (no origin contact)")
                    continue
                # a miss fetches from the origin, relays verbatim, and caches it.
                fetched = origin_client.send(Method.READ, "/page")
                proxy_srv.relay(conn, stream, fetched)
                cache.put_signed(
                    Method.READ, "/page", fetched, origin_pubkey, now_secs()
                )
                fetched.close()
                print("  proxy: fetched origin, relayed + cached")

        with DrivenServer(proxy_srv, on_tick=serve_parked) as proxy:
            client = (
                Client.builder()
                .identity(Identity.generate())
                .connect(proxy.node_id, Address.loopback(proxy.port))
            )
            with client:
                for i in (1, 2):
                    with client.send(Method.READ, "/page") as resp:
                        print(f"client hit {i}: {resp.status} {resp.body!r}")
                        assert resp.body == ORIGIN_BODY
                print(f"cache stats: {cache.stats()}")

        cache.close()
        origin_client.close()
        proxy_id.close()


if __name__ == "__main__":
    main()
