"""nwcurl, a curl/httpie for web/1 (mirrors sandbox/003-nwcurl).

drives the full client surface: a unary read printing the status and every header
(like curl -i) and verifying the response against the connected peer, then a
streamed read reassembled and signature-verified. a tiny server makes it
self-contained; the point is the client side.

    python examples/nwcurl.py
"""

from __future__ import annotations

import threading

from _common import DrivenServer
from nwep import Address, Client, Identity, Method, Server, Status

BIG = bytes((i * 7 + 3) % 256 for i in range(120_000))  # a body served as a stream.
pending: list[tuple[int, int]] = []
lock = threading.Lock()


def handler(req, res):
    if req.path == "/hello":
        return (
            res.header("content-type", "text/plain")
            .header("x-demo", "1")
            .ok(b"hi from web/1")
        )
    if req.path == "/big":
        with lock:
            pending.append((req.conn_id, req.stream_id))
        return res.stream(
            "/big", Status.OK, {"content-type": "application/octet-stream"}
        )
    return res.not_found()


def main() -> None:
    srv = (
        Server.builder()
        .identity(Identity.generate())
        .bind(Address.loopback(0))
        .on_request(handler)
        .build()
    )

    active: list[list[int]] = []

    def pump_streams():
        with lock:
            while pending:
                active.append([*pending.pop(0), 0])
        still = []
        for conn, stream, sent in active:
            while sent < len(BIG):
                took = srv.stream_send(conn, stream, BIG[sent:])
                sent += took
                if took == 0:
                    break
            if sent < len(BIG):
                still.append([conn, stream, sent])
            else:
                srv.stream_end(conn, stream)
        active[:] = still

    with DrivenServer(srv, on_tick=pump_streams) as node:
        client = (
            Client.builder()
            .identity(Identity.generate())
            .connect(node.node_id, Address.loopback(node.port))
        )
        with client:
            # curl -i: status line + every header.
            with client.send(Method.READ, "/hello") as resp:
                print(f"GET /hello -> {resp.status}")
                for name, value in resp.headers():
                    print(f"  {name}: {value}")
                client.verify_response(resp, "/hello")  # -k: verify against the peer.
                print(f"  (signature verified) body {resp.body!r}")

            # a streamed read, reassembled and verified.
            stream = client.open_stream(Method.READ, "/big")
            with stream:
                stream.response().close()
                received = bytearray()
                while True:
                    chunk, ended = stream.recv()
                    received += chunk
                    if ended:
                        break
                stream.verify(client.peer_pubkey)
            print(
                f"GET /big (stream) -> {len(received)} bytes, trailer signature verified"
            )
            assert bytes(received) == BIG


if __name__ == "__main__":
    main()
