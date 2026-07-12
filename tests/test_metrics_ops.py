"""metrics + server-ops tests NW000017: observability, load, drain, compression.

server and client metrics snapshots, the load gauge + set_overloaded, the graceful
drain, negotiated compression, the last-handshake-error diagnostic, and the
max_parked builder cap  -  all over a real connection. core library, no trust.
"""

from __future__ import annotations

import threading
import time

from nwep import Address, Client, Compression, Identity, Method, Server


def now_ms() -> int:
    return int(time.monotonic() * 1000)


def _run(server) -> tuple[threading.Event, threading.Thread]:
    stop = threading.Event()

    def loop():
        while not stop.is_set():
            server.tick(now_ms())
            time.sleep(0.002)

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()
    return stop, thread


def test_server_and_client_metrics_reflect_a_request() -> None:
    server_identity = Identity.generate()
    server = (
        Server.builder()
        .identity(server_identity)
        .bind(Address.loopback(0))
        .on_request(lambda req, res: res.ok(b"ok"))
        .build()
    )
    stop, thread = _run(server)
    try:
        # a fresh server has no connections.
        m0 = server.metrics()
        assert m0.connections_active == 0
        assert m0.requests_dispatched == 0
        assert 0 <= server.load <= 100

        with (
            Client.builder()
            .identity(Identity.generate())
            .connect(server.node_id, Address.loopback(server.local_port)) as client
        ):
            client.send(Method.READ, "/a").close()
            client.send(Method.READ, "/b").close()

            # the server saw the connection and dispatched the requests.
            m1 = server.metrics()
            assert m1.connections_accepted >= 1
            assert m1.requests_dispatched >= 2
            assert m1.datagrams_received > 0

            # the client tracks its connection's health and rtt.
            cm = client.metrics()
            assert cm.alive is True
            assert isinstance(cm.smoothed_rtt_us, int)

            # both endpoints report a negotiated compression codec.
            assert isinstance(client.compression, Compression)
    finally:
        stop.set()
        thread.join(timeout=2)
        server.close()
        server_identity.close()


def test_set_overloaded_drives_the_load_gauge() -> None:
    identity = Identity.generate()
    server = (
        Server.builder()
        .identity(identity)
        .bind(Address.loopback(0))
        .on_request(lambda r, s: s.ok(b""))
        .build()
    )
    try:
        assert server.load < 100
        server.set_overloaded(True)
        assert server.load == 100  # forced to the ceiling.
        server.set_overloaded(False)
        assert server.load < 100
    finally:
        server.close()
        identity.close()


def test_graceful_drain_completes_when_idle() -> None:
    identity = Identity.generate()
    server = (
        Server.builder()
        .identity(identity)
        .bind(Address.loopback(0))
        .on_request(lambda r, s: s.ok(b""))
        .build()
    )
    try:
        assert server.is_drained is False
        server.drain()
        # no connections were ever made, so the drain completes after a tick.
        for _ in range(50):
            server.tick(now_ms())
            if server.is_drained:
                break
            time.sleep(0.005)
        assert server.is_drained is True
    finally:
        server.close()
        identity.close()


def test_last_handshake_error_is_none_when_no_inbound_rejection() -> None:
    # the server-side diagnostic records INBOUND handshake rejections (the server
    # turning a client away). a healthy server that has rejected nobody reports
    # None; this verifies the 0 -> None wrapping and that a normal request flow
    # leaves it clear (a client dialing the wrong server node_id fails client-side
    # and is not an inbound rejection the server records).
    identity = Identity.generate()
    server = (
        Server.builder()
        .identity(identity)
        .bind(Address.loopback(0))
        .on_request(lambda r, s: s.ok(b""))
        .build()
    )
    stop, thread = _run(server)
    try:
        assert server.last_handshake_error() is None
        with (
            Client.builder()
            .identity(Identity.generate())
            .connect(server.node_id, Address.loopback(server.local_port)) as client
        ):
            client.send(Method.READ, "/ok").close()
        assert server.last_handshake_error() is None  # a clean handshake, no rejection.
    finally:
        stop.set()
        thread.join(timeout=2)
        server.close()
        identity.close()


def test_max_parked_is_a_builder_option() -> None:
    identity = Identity.generate()
    # just assert the option builds cleanly and the server is usable.
    server = (
        Server.builder()
        .identity(identity)
        .bind(Address.loopback(0))
        .max_parked(8)
        .on_request(lambda r, s: s.ok(b""))
        .build()
    )
    try:
        assert server.metrics().parked_active == 0
    finally:
        server.close()
        identity.close()
