"""streaming tests NW060200: a server streams a large body, a client pulls it.

the server side (Responder.stream + Server.stream_send/stream_end) and the client
side (Client.open_stream -> Stream.response/recv/verify) over a real connection.
the server is driven on a background thread; it parks each /big request and drains
the body across ticks under back-pressure. core library, no trust.
"""

from __future__ import annotations

import selectors
import threading
import time

from nwep import Address, Client, Identity, Method, Server, Status

# a body well over one chunk, to force chunked streaming and back-pressure.
BODY = bytes((i * 31 + 7) % 256 for i in range(300_000))


def now_ms() -> int:
    return int(time.monotonic() * 1000)


def test_server_streams_a_large_body_client_reassembles_and_verifies() -> None:
    server_identity = Identity.generate()
    pending: list[tuple[int, int]] = []
    pending_lock = threading.Lock()

    def handler(req, res):
        if req.path == "/big":
            with pending_lock:
                pending.append((req.conn_id, req.stream_id))
            return res.stream(
                "/big", Status.OK, {"content-type": "application/octet-stream"}
            )
        return res.not_found()

    server = (
        Server.builder()
        .identity(server_identity)
        .bind(Address.loopback(0))
        .on_request(handler)
        .build()
    )

    stop = threading.Event()

    def loop():
        sel = selectors.DefaultSelector()
        sel.register(server, selectors.EVENT_READ)
        # streams the server is actively draining: (conn, stream, bytes_sent).
        active: list[list[int]] = []
        while not stop.is_set():
            sel.select(timeout=min(0.01, (server.next_timeout(now_ms()) or 10) / 1000))
            server.tick(now_ms())
            with pending_lock:
                while pending:
                    conn, stream = pending.pop(0)
                    active.append([conn, stream, 0])
            still = []
            for conn, stream, sent in active:
                while sent < len(BODY):
                    took = server.stream_send(conn, stream, BODY[sent:])
                    sent += took
                    if took == 0:
                        break  # back-pressure; let tick drain, resume next pass.
                if sent < len(BODY):
                    still.append([conn, stream, sent])
                else:
                    server.stream_end(conn, stream)
            active = still

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()

    try:
        with (
            Client.builder()
            .identity(Identity.generate())
            .connect(server.node_id, Address.loopback(server.local_port)) as client
        ):
            stream = client.open_stream(Method.READ, "/big")
            with stream:
                meta = stream.response()
                with meta:
                    assert meta.status == Status.OK
                    assert meta.header("content-type") == "application/octet-stream"

                received = bytearray()
                while True:
                    chunk, ended = stream.recv()
                    received += chunk
                    if ended:
                        break

                assert len(received) == len(BODY)
                assert bytes(received) == BODY  # the streamed body is byte-exact.

                # the trailer carries the response signature; it verifies against
                # the server's key NW060900.
                stream.verify(client.peer_pubkey)
    finally:
        stop.set()
        thread.join(timeout=3)
        server.close()
        server_identity.close()


def test_stream_send_back_pressure_returns_partial_counts() -> None:
    # stream_send returns how many bytes it accepted, which can be < len under
    # back-pressure; the loop above relies on that to resume the unaccepted tail.
    # here we just assert the accounting reaches the full body across passes.
    server_identity = Identity.generate()
    pending: list[tuple[int, int]] = []
    lock = threading.Lock()

    def handler(req, res):
        with lock:
            pending.append((req.conn_id, req.stream_id))
        return res.stream("/s", Status.OK)

    server = (
        Server.builder()
        .identity(server_identity)
        .bind(Address.loopback(0))
        .on_request(handler)
        .build()
    )
    stop = threading.Event()
    total_sent = {"n": 0}

    def loop():
        active: list[list[int]] = []
        while not stop.is_set():
            server.tick(now_ms())
            with lock:
                while pending:
                    active.append([*pending.pop(0), 0])
            still = []
            for conn, stream, sent in active:
                took = (
                    server.stream_send(conn, stream, BODY[sent:])
                    if sent < len(BODY)
                    else 0
                )
                sent += took
                total_sent["n"] += took
                if sent < len(BODY):
                    still.append([conn, stream, sent])
                else:
                    server.stream_end(conn, stream)
            active = still
            time.sleep(0.001)

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()
    try:
        with (
            Client.builder()
            .identity(Identity.generate())
            .connect(server.node_id, Address.loopback(server.local_port)) as client
        ):
            with client.open_stream(Method.READ, "/s") as stream:
                stream.response().close()
                got = 0
                while True:
                    chunk, ended = stream.recv()
                    got += len(chunk)
                    if ended:
                        break
                assert got == len(BODY)
                assert total_sent["n"] == len(BODY)  # every byte accounted for.
    finally:
        stop.set()
        thread.join(timeout=3)
        server.close()
        server_identity.close()
