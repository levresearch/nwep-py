"""range + conditional tests NW060700 NW060800: the nwserve content-serving pattern.

a handler serves a resource with an etag: a conditional read whose if-none-match
matches gets not-modified; a range request gets partial-content; an out-of-bounds
range gets range-not-satisfiable; an unconditional read gets the whole body. driven
over a real connection. core library, no trust.
"""

from __future__ import annotations

import hashlib
import threading
import time

import nwep
from nwep import Address, Client, Identity, Method, RangeKind, Server, Status

RESOURCE = bytes(range(256)) * 4  # 1024 bytes, content of a /doc resource.
ETAG = '"' + hashlib.sha256(RESOURCE).hexdigest()[:16] + '"'


def now_ms() -> int:
    return int(time.monotonic() * 1000)


def _serve_content():
    """a content handler implementing the spec 6.7 + 6.8 flow (the nwserve app)."""

    def handler(req, res):
        if req.path != "/doc":
            return res.not_found()
        if req.is_fresh(ETAG):
            return res.not_modified(ETAG)
        outcome = req.range(len(RESOURCE), ETAG)
        if outcome.kind is RangeKind.RANGES:
            return res.header("etag", ETAG).partial(
                RESOURCE, outcome.ranges, "application/octet-stream"
            )
        if outcome.kind is RangeKind.UNSATISFIABLE:
            return res.range_not_satisfiable(len(RESOURCE))
        return (
            res.header("etag", ETAG)
            .header("content-type", "application/octet-stream")
            .ok(RESOURCE)
        )

    identity = Identity.generate()
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


def test_content_serving_etag_and_ranges() -> None:
    server, identity, stop, thread = _serve_content()
    try:
        with (
            Client.builder()
            .identity(Identity.generate())
            .connect(server.node_id, Address.loopback(server.local_port)) as client
        ):
            # unconditional read: the whole body with its etag.
            with client.send(Method.READ, "/doc") as resp:
                assert resp.status == Status.OK
                assert resp.body == RESOURCE
                assert resp.header("etag") == ETAG

            # conditional read whose etag matches: not-modified, no body.
            with client.send(
                Method.READ, "/doc", headers={"if-none-match": ETAG}
            ) as resp:
                assert resp.status == Status.NOT_MODIFIED
                assert resp.body == b""

            # a stale etag still gets the full body.
            with client.send(
                Method.READ, "/doc", headers={"if-none-match": '"stale"'}
            ) as resp:
                assert resp.status == Status.OK
                assert resp.body == RESOURCE

            # a byte range: partial-content with just those bytes.
            with client.send(
                Method.READ, "/doc", headers={"range": "bytes=0-99"}
            ) as resp:
                assert resp.status == Status.PARTIAL_CONTENT
                assert resp.body == RESOURCE[0:100]  # inclusive [0, 99].
                assert "0-99/1024" in (resp.header("content-range") or "")

            # a suffix range (last 50 bytes).
            with client.send(
                Method.READ, "/doc", headers={"range": "bytes=-50"}
            ) as resp:
                assert resp.status == Status.PARTIAL_CONTENT
                assert resp.body == RESOURCE[-50:]

            # an out-of-bounds range: range-not-satisfiable.
            with client.send(
                Method.READ, "/doc", headers={"range": "bytes=99999-100000"}
            ) as resp:
                assert resp.status == Status.RANGE_NOT_SATISFIABLE
    finally:
        stop.set()
        thread.join(timeout=2)
        server.close()
        identity.close()


def test_responder_partial_requires_ranges() -> None:
    # the guard is a pure value check; assert it without a live connection by
    # building a responder over a null buf (partial raises before touching it).
    from nwep.server import Responder

    res = Responder(nwep._ffi.NULL, nwep._ffi.NULL, 1, 1)
    import pytest

    with pytest.raises(ValueError):
        res.partial(b"body", [], "text/plain")
