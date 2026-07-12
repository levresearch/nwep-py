"""log-server tests NW000014: /log/* routing behind a real quic server.

a LogServer runs inside a server handler, routing /log/* through dispatch and
falling through otherwise. a client submits a key-binding over WRITE /log/entry
(the on_append hook fires), reads /log/root, and a non-log path is answered by the
handler. core library  -  the log server has no bls dependency.
"""

from __future__ import annotations

import hashlib
import selectors
import threading
import time

from nwep import (
    Address,
    Client,
    Identity,
    KeyBinding,
    Log,
    LogServer,
    Method,
    Server,
    Status,
)


def now_ms() -> int:
    return int(time.monotonic() * 1000)


def now_secs() -> int:
    return int(time.time())


def test_log_server_routes_writes_reads_and_falls_through() -> None:
    server_identity = Identity.generate()
    log = Log()
    log_server = LogServer(server_identity, log)

    appended: list[tuple[bytes, int]] = []
    log_server.on_append(lambda entry, index: appended.append((entry, index)))

    def handler(req, res):
        reply = log_server.dispatch(req, res, now_secs())
        if reply is not None:
            return reply  # a /log/* route, answered by the log server.
        return res.ok(b"app-handled") if req.path == "/app" else res.not_found()

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
        while not stop.is_set():
            sel.select(timeout=min(0.02, (server.next_timeout(now_ms()) or 20) / 1000))
            server.tick(now_ms())

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()

    try:
        # a submitter publishes its own key binding via write /log/entry.
        with Identity.generate() as submitter, Identity.generate() as recovery:
            commitment = hashlib.sha256(recovery.public_key).digest()
            entry = KeyBinding.create(submitter, commitment, now_secs())

            with (
                Client.builder()
                .identity(submitter)
                .connect(server.node_id, Address.loopback(server.local_port)) as client
            ):
                # the log server accepts the entry and answers created.
                with client.send(Method.WRITE, "/log/entry", body=entry) as resp:
                    assert resp.status == Status.CREATED
                assert appended == [(entry, 0)], "on_append fired once with entry 0"
                assert log.size == 1

                # read /log/root is a log route too. its body is
                # [8B log_size_be][32B merkle_root] NW121000, for rollback
                # detection via size monotonicity), 40 bytes total.
                with client.send(Method.READ, "/log/root") as resp:
                    assert resp.status == Status.OK
                    assert len(resp.body) == 40
                    assert int.from_bytes(resp.body[:8], "big") == 1  # one entry.
                    assert resp.body[8:] == log.root()  # the live merkle root.

                # a non-/log path falls through to the application handler.
                with client.send(Method.READ, "/app") as resp:
                    assert resp.status == Status.OK
                    assert resp.body == b"app-handled"

                with client.send(Method.READ, "/nope") as resp:
                    assert resp.status == Status.NOT_FOUND
    finally:
        stop.set()
        thread.join(timeout=2)
        log_server.close()
        log.close()
        server.close()
        server_identity.close()


def test_on_append_can_be_cleared() -> None:
    with Identity.generate() as identity, Log() as log:
        ls = LogServer(identity, log)
        ls.on_append(lambda e, i: None)
        ls.on_append(None)  # clearing is a no-op that must not crash.
        ls.close()
        ls.close()  # idempotent.
