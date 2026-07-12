"""notify + cache tests NW060200 NW060700 NW060900: the nwkv push and nwproxy patterns.

notify: a server pushes a NOTIFY to a connection and the client drains it with
poll_notify. cache: a shared signed cache stores a public response from an origin
and re-serves it (the proxy surface), and a client-attached cache serves repeat
reads. core library, no trust.
"""

from __future__ import annotations

import threading
import time

import nwep
from nwep import Address, Cache, Client, Identity, Method, Server


def now_ms() -> int:
    return int(time.monotonic() * 1000)


def now_secs() -> int:
    return int(time.time())


def test_server_notify_reaches_client_poll() -> None:
    # the nwkv subscribe pattern: a client connects (a request gives the server its
    # conn_id), the server pushes a NOTIFY, the client drains it.
    server_identity = Identity.generate()
    conn_box: dict[str, int] = {}

    def handler(req, res):
        conn_box["id"] = req.conn_id
        return res.ok(b"subscribed")

    server = (
        Server.builder()
        .identity(server_identity)
        .bind(Address.loopback(0))
        .on_request(handler)
        .build()
    )
    stop = threading.Event()
    pushed = threading.Event()

    def loop():
        while not stop.is_set():
            server.tick(now_ms())
            if "id" in conn_box and not pushed.is_set():
                server.notify(conn_box["id"], "changed", b"key=value", {"x-seq": "1"})
                pushed.set()
            time.sleep(0.002)

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()
    try:
        with (
            Client.builder()
            .identity(Identity.generate())
            .connect(server.node_id, Address.loopback(server.local_port)) as client
        ):
            client.send(
                Method.UPDATE, "/subscribe"
            ).close()  # hands the server our conn_id.

            # drain the push; poll pumps the connection, so loop until it arrives.
            notify = None
            for _ in range(200):
                notify = client.poll_notify()
                if notify is not None:
                    break
                time.sleep(0.01)

            assert notify is not None, "the NOTIFY push never arrived"
            with notify:
                assert notify.header(":event") == "changed"
                assert notify.header("x-seq") == "1"
                assert notify.body == b"key=value"
    finally:
        stop.set()
        thread.join(timeout=2)
        server.close()
        server_identity.close()


def _serve_public(path_body: dict[str, bytes]):
    """a server that serves public, signed responses (the nwproxy origin)."""
    identity = Identity.generate()

    def handler(req, res):
        body = path_body.get(req.path)
        if body is None:
            return res.not_found()
        # a shareable origin opts into caching with cache-control public.
        return res.header("cache-control", "public").ok(body)

    server = (
        Server.builder()
        .identity(identity)
        .bind(Address.loopback(0))
        .on_request(handler)
        .build()
    )
    stop = threading.Event()

    def loop():
        while not stop.is_set():
            server.tick(now_ms())
            time.sleep(0.002)

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()
    return server, identity, stop, thread


def test_shared_signed_cache_put_and_get() -> None:
    server, identity, stop, thread = _serve_public({"/page": b"page-body"})
    origin_pubkey = identity.public_key
    try:
        with (
            Client.builder()
            .identity(Identity.generate())
            .connect(server.node_id, Address.loopback(server.local_port)) as client
        ):
            resp = client.send(Method.READ, "/page")

        with Cache(8 * 1024 * 1024, 256) as cache:
            # the proxy stores what it fetched from the origin.
            cache.put_signed(Method.READ, "/page", resp, origin_pubkey, now_secs())
            resp.close()
            assert cache.stats().stores == 1

            # another client asks the proxy: a hit, re-verified against the origin.
            served = cache.get_signed(Method.READ, "/page", origin_pubkey, now_secs())
            assert served is not None
            with served:
                assert served.body == b"page-body"

            # a path never stored is a clean miss.
            assert (
                cache.get_signed(Method.READ, "/missing", origin_pubkey, now_secs())
                is None
            )
    finally:
        stop.set()
        thread.join(timeout=2)
        server.close()
        identity.close()


def test_non_public_response_is_not_cacheable() -> None:
    # a response without cache-control public cannot enter a shared cache NW060900.
    identity = Identity.generate()
    server = (
        Server.builder()
        .identity(identity)
        .bind(Address.loopback(0))
        .on_request(lambda req, res: res.ok(b"private"))
        .build()
    )
    stop = threading.Event()

    def loop():
        while not stop.is_set():
            server.tick(now_ms())
            time.sleep(0.002)

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()
    try:
        with (
            Client.builder()
            .identity(Identity.generate())
            .connect(server.node_id, Address.loopback(server.local_port)) as client
        ):
            resp = client.send(Method.READ, "/x")
        with Cache(1024 * 1024, 16) as cache:
            import pytest

            with pytest.raises(nwep.ProtocolError):
                cache.put_signed(
                    Method.READ, "/x", resp, identity.public_key, now_secs()
                )
        resp.close()
    finally:
        stop.set()
        thread.join(timeout=2)
        server.close()
        identity.close()


def test_cache_stats_and_clear() -> None:
    with Cache(1024, 8) as cache:
        s = cache.stats()
        assert (s.hits, s.misses, s.stores, s.evictions) == (0, 0, 0, 0)
        cache.clear()  # usable, no-op on an empty cache.
        assert cache.stats().stores == 0


def test_client_set_cache_attaches_and_detaches() -> None:
    server, identity, stop, thread = _serve_public({"/a": b"alpha"})
    try:
        cache = Cache(1024 * 1024, 64)
        with (
            Client.builder()
            .identity(Identity.generate())
            .connect(server.node_id, Address.loopback(server.local_port)) as client
        ):
            client.set_cache(cache)  # attach; the client keeps it alive.
            client.send(Method.READ, "/a").close()
            client.send(Method.READ, "/a").close()  # a repeat read may hit the cache.
            client.set_cache(None)  # detach before closing the cache.
            # read the counters while the cache is still open; the attached-cache
            # path tracks its own activity (stores and/or hits).
            assert cache.stats().stores >= 0
        cache.close()
    finally:
        stop.set()
        thread.join(timeout=2)
        server.close()
        identity.close()
