"""nwserve, a static content server (mirrors sandbox/001-nwserve).

serves a resource with an etag, byte ranges NW060800, and conditional reads
NW060700  -  the content path nginx-style serving rests on. a client fetches the
whole resource, a sub-range, a suffix range, an out-of-bounds range, and a fresh
conditional read, printing each outcome.

    python examples/nwserve.py
"""

from __future__ import annotations

import hashlib

from _common import DrivenServer
from nwep import Address, Client, Identity, Method, RangeKind, Server, Status

RESOURCE = bytes(range(256)) * 4  # a 1024-byte resource served at /doc.
ETAG = '"' + hashlib.sha256(RESOURCE).hexdigest()[:16] + '"'


def handler(req, res):
    if req.path != "/doc":
        return res.not_found()
    if req.is_fresh(ETAG):
        return res.not_modified(ETAG)  # conditional read whose etag matched.
    outcome = req.range(len(RESOURCE), ETAG)
    if outcome.kind is RangeKind.RANGES:
        return res.header("etag", ETAG).partial(
            RESOURCE, outcome.ranges, "application/octet-stream"
        )
    if outcome.kind is RangeKind.UNSATISFIABLE:
        return res.range_not_satisfiable(len(RESOURCE))
    return res.header("etag", ETAG).ok(RESOURCE)


def main() -> None:
    srv = (
        Server.builder()
        .identity(Identity.generate())
        .bind(Address.loopback(0))
        .on_request(handler)
        .build()
    )
    with DrivenServer(srv) as node:
        client = (
            Client.builder()
            .identity(Identity.generate())
            .connect(node.node_id, Address.loopback(node.port))
        )
        with client:
            with client.send(Method.READ, "/doc") as r:
                print(
                    f"read /doc                {r.status} {len(r.body)} bytes, etag {r.header('etag')}"
                )

            with client.send(Method.READ, "/doc", headers={"if-none-match": ETAG}) as r:
                print(f"read /doc if-none-match  {r.status} (body {len(r.body)} bytes)")

            with client.send(Method.READ, "/doc", headers={"range": "bytes=0-99"}) as r:
                print(
                    f"read /doc bytes=0-99     {r.status} {len(r.body)} bytes, {r.header('content-range')}"
                )

            with client.send(Method.READ, "/doc", headers={"range": "bytes=-50"}) as r:
                print(
                    f"read /doc bytes=-50      {r.status} {len(r.body)} bytes (suffix)"
                )

            with client.send(
                Method.READ, "/doc", headers={"range": "bytes=99999-100000"}
            ) as r:
                print(f"read /doc out-of-bounds  {r.status}")
                assert r.status is Status.RANGE_NOT_SATISFIABLE


if __name__ == "__main__":
    main()
