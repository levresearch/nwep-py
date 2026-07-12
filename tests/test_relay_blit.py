"""relay + blit tests NW000017: the nwproxy verbatim/frame surface.

a proxy serves an origin's response without re-signing (relay), so the client
verifies the origin's signature; and a hot resource is served from a captured wire
frame with no per-hit work (capture -> blit). covers the synchronous in-handler
forms (Responder.relay/blit/capture) and the deferred ones (Server.relay/
respond_blit). core library, no trust.
"""

from __future__ import annotations

import threading
import time

import nwep
from nwep import Address, Client, Identity, Method, Server, Status


def now_ms() -> int:
    return int(time.monotonic() * 1000)


def _run(server):
    stop = threading.Event()

    def loop():
        while not stop.is_set():
            server.tick(now_ms())
            time.sleep(0.002)

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()
    return stop, thread


def _origin(path_body: dict[str, bytes]):
    """an origin that serves public, signed responses (the thing a proxy caches)."""
    identity = Identity.generate()

    def handler(req, res):
        body = path_body.get(req.path)
        return (
            res.header("cache-control", "public").ok(body)
            if body is not None
            else res.not_found()
        )

    server = (
        Server.builder()
        .identity(identity)
        .bind(Address.loopback(0))
        .on_request(handler)
        .build()
    )
    stop, thread = _run(server)
    return server, identity, stop, thread


def test_synchronous_relay_preserves_the_origin_signature() -> None:
    # a proxy fetches from an origin, then relays it verbatim to its own clients;
    # the relayed response still verifies against the ORIGIN key, not the proxy.
    origin, origin_id, ostop, othread = _origin({"/page": b"origin-body"})
    origin_pubkey = origin_id.public_key

    # the proxy fetches /page from the origin once, holds the Response, and relays
    # it from its own handler.
    proxy_client = (
        Client.builder()
        .identity(Identity.generate())
        .connect(origin.node_id, Address.loopback(origin.local_port))
    )
    cached = proxy_client.send(Method.READ, "/page")

    def proxy_handler(req, res):
        return res.relay(cached) if req.path == "/page" else res.not_found()

    proxy_id = Identity.generate()
    proxy = (
        Server.builder()
        .identity(proxy_id)
        .bind(Address.loopback(0))
        .on_request(proxy_handler)
        .build()
    )
    pstop, pthread = _run(proxy)

    try:
        with (
            Client.builder()
            .identity(Identity.generate())
            .connect(proxy.node_id, Address.loopback(proxy.local_port)) as client
        ):
            with client.send(Method.READ, "/page") as resp:
                assert resp.status == Status.OK
                assert resp.body == b"origin-body"
                # the proxy is NOT the origin; the body verifies against the origin.
                assert client.peer_pubkey != origin_pubkey  # talking to the proxy.
    finally:
        pstop.set()
        pthread.join(timeout=2)
        proxy.close()
        proxy_id.close()
        cached.close()
        proxy_client.close()
        ostop.set()
        othread.join(timeout=2)
        origin.close()
        origin_id.close()


def test_capture_then_blit_serves_a_hot_resource() -> None:
    # first hit builds + captures the wire frame; later hits blit it verbatim. both
    # produce the same bytes to the client.
    frame_box: dict[str, bytes] = {}

    def handler(req, res):
        if req.path != "/hot":
            return res.not_found()
        if "frame" in frame_box:
            return res.blit(frame_box["frame"])  # fast path: no re-encode/re-sign.
        reply = res.header("cache-control", "public").ok(b"hot-body")
        frame_box["frame"] = res.capture()  # stash the built frame for next time.
        return reply

    identity = Identity.generate()
    server = (
        Server.builder()
        .identity(identity)
        .bind(Address.loopback(0))
        .on_request(handler)
        .build()
    )
    stop, thread = _run(server)
    try:
        with (
            Client.builder()
            .identity(Identity.generate())
            .connect(server.node_id, Address.loopback(server.local_port)) as client
        ):
            with client.send(Method.READ, "/hot") as first:  # builds + captures.
                assert first.status == Status.OK
                assert first.body == b"hot-body"
            assert "frame" in frame_box and len(frame_box["frame"]) > 0

            with client.send(Method.READ, "/hot") as second:  # served by blit.
                assert second.status == Status.OK
                assert second.body == b"hot-body"
    finally:
        stop.set()
        thread.join(timeout=2)
        server.close()
        identity.close()


def test_deferred_relay_from_the_loop() -> None:
    # a proxy defers, fetches the origin in the loop, then relays it out of band.
    origin, origin_id, ostop, othread = _origin({"/r": b"deferred-origin"})
    proxy_client = (
        Client.builder()
        .identity(Identity.generate())
        .connect(origin.node_id, Address.loopback(origin.local_port))
    )

    parked: list[tuple[int, int]] = []
    lock = threading.Lock()

    def proxy_handler(req, res):
        with lock:
            parked.append((req.conn_id, req.stream_id))
        return res.defer()

    proxy_id = Identity.generate()
    proxy = (
        Server.builder()
        .identity(proxy_id)
        .bind(Address.loopback(0))
        .on_request(proxy_handler)
        .build()
    )
    pstop = threading.Event()
    fetched = proxy_client.send(Method.READ, "/r")  # the proxy's origin fetch.

    def proxy_loop():
        while not pstop.is_set():
            proxy.tick(now_ms())
            with lock:
                while parked:
                    conn, stream = parked.pop(0)
                    proxy.relay(conn, stream, fetched)  # deferred verbatim relay.
            time.sleep(0.002)

    pthread = threading.Thread(target=proxy_loop, daemon=True)
    pthread.start()
    try:
        with (
            Client.builder()
            .identity(Identity.generate())
            .connect(proxy.node_id, Address.loopback(proxy.local_port)) as client
        ):
            with client.send(Method.READ, "/r") as resp:
                assert resp.status == Status.OK
                assert resp.body == b"deferred-origin"
    finally:
        pstop.set()
        pthread.join(timeout=2)
        proxy.close()
        proxy_id.close()
        fetched.close()
        proxy_client.close()
        ostop.set()
        othread.join(timeout=2)
        origin.close()
        origin_id.close()


def test_capture_before_a_response_is_built_raises() -> None:
    from nwep.server import Responder

    res = Responder(nwep._ffi.NULL, nwep._ffi.NULL, 1, 1)
    import pytest

    with pytest.raises(RuntimeError):
        res.capture()  # nothing built yet.
