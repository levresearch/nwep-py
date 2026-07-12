"""round-trip tests NW060000: a real client talking to a real server.

this is where the server slice's handler dispatch is finally exercised end to end
and where the client slice is validated. the server is driven on a background
thread; the blocking client connect/send run on the main thread, each driving
their own side of the exchange while the server thread ticks.
"""

from __future__ import annotations

import selectors
import threading
import time


from nwep import Address, Client, Identity, Method, Server, Status


def now_ms() -> int:
    return int(time.monotonic() * 1000)


class RunningServer:
    """a server driven on its own thread for the duration of a test."""

    def __init__(self, handler):
        self.identity = Identity.generate()
        self.server = (
            Server.builder()
            .identity(self.identity)
            .bind(Address.loopback(0))
            .on_request(handler)
            .build()
        )
        self.node_id = self.server.node_id
        self.port = self.server.local_port
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self):
        sel = selectors.DefaultSelector()
        sel.register(self.server, selectors.EVENT_READ)
        while not self._stop.is_set():
            timeout = self.server.next_timeout(now_ms())
            sel.select(timeout=min(0.02, (timeout or 20) / 1000))
            self.server.tick(now_ms())

    def address(self) -> Address:
        return Address.loopback(self.port)

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=2)
        self.server.close()


def _client_to(running: RunningServer) -> Client:
    return (
        Client.builder()
        .identity(Identity.generate())
        .connect(running.node_id, running.address())
    )


def test_request_reaches_handler_and_response_comes_back() -> None:
    def handler(req, res):
        if req.path == "/hello":
            return res.ok(b"hi from web/1")
        return res.not_found()

    running = RunningServer(handler)
    try:
        with _client_to(running) as client:
            with client.send(Method.READ, "/hello") as resp:
                assert resp.status == Status.OK
                assert resp.body == b"hi from web/1"
            with client.send(Method.READ, "/missing") as resp:
                assert resp.status == Status.NOT_FOUND
    finally:
        running.stop()


def test_handler_sees_method_path_and_request_headers() -> None:
    seen = {}

    def handler(req, res):
        seen["method"] = req.method
        seen["path"] = req.path
        seen["x-trace"] = req.header("x-trace")
        seen["headers"] = dict(req.headers())
        return res.ok(b"")

    running = RunningServer(handler)
    try:
        with _client_to(running) as client:
            client.send(
                Method.WRITE, "/put", body=b"payload", headers={"x-trace": "abc123"}
            ).close()
    finally:
        running.stop()

    assert seen["method"] == Method.WRITE
    assert seen["path"] == "/put"
    assert seen["x-trace"] == "abc123"
    assert seen["headers"].get("x-trace") == "abc123"


def test_handler_reads_authenticated_peer_node_id() -> None:
    client_identity = Identity.generate()
    captured = {}

    def handler(req, res):
        captured["peer"] = req.peer_node_id
        return res.ok(b"")

    running = RunningServer(handler)
    try:
        client = (
            Client.builder()
            .identity(client_identity)
            .connect(running.node_id, running.address())
        )
        with client:
            client.send(Method.READ, "/whoami").close()
    finally:
        running.stop()

    # the server authenticated the client's real node_id in the handshake.
    assert captured["peer"] == client_identity.node_id


def test_response_headers_round_trip() -> None:
    def handler(req, res):
        return res.header("content-type", "text/plain").header("etag", "v1").ok(b"body")

    running = RunningServer(handler)
    try:
        with _client_to(running) as client, client.send(Method.READ, "/doc") as resp:
            assert resp.status == Status.OK
            assert resp.header("content-type") == "text/plain"
            assert resp.header("etag") == "v1"
            assert dict(resp.headers()).get("content-type") == "text/plain"
    finally:
        running.stop()


def test_deferred_response_is_answered_from_the_loop() -> None:
    # the handler defers; a background tick answers it via Server.respond.
    parked = []

    def handler(req, res):
        parked.append((req.conn_id, req.stream_id))
        return res.defer()

    running = RunningServer(handler)

    # a second thread drains parked requests and answers them out of band.
    stop = threading.Event()

    def answerer():
        while not stop.is_set():
            while parked:
                conn, stream = parked.pop(0)
                running.server.respond(conn, stream, Status.CREATED, b"done later")
            time.sleep(0.002)

    answer_thread = threading.Thread(target=answerer, daemon=True)
    answer_thread.start()
    try:
        with _client_to(running) as client, client.send(Method.WRITE, "/async") as resp:
            assert resp.status == Status.CREATED
            assert resp.body == b"done later"
    finally:
        stop.set()
        answer_thread.join(timeout=2)
        running.stop()


def test_client_reports_alive_then_dead_after_close() -> None:
    running = RunningServer(lambda req, res: res.ok(b""))
    try:
        client = _client_to(running)
        assert client.is_alive()
        assert client.fileno() >= 0
        client.close()
        assert repr(client) == "Client(closed)"
    finally:
        running.stop()


def test_handler_exception_does_not_crash_the_server() -> None:
    # an exception in the handler must not unwind into c; the server stays up and
    # the peer gets an error response NWG0900.
    def handler(req, res):
        if req.path == "/boom":
            raise RuntimeError("handler blew up")
        return res.ok(b"fine")

    running = RunningServer(handler)
    try:
        with _client_to(running) as client:
            with client.send(Method.READ, "/boom") as resp:
                assert resp.status is not None  # got SOME response, not a crash
            # the server survived the exception and still serves.
            with client.send(Method.READ, "/ok") as resp:
                assert resp.status == Status.OK
                assert resp.body == b"fine"
    finally:
        running.stop()
