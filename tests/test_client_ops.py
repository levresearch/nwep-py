"""client-ops tests NW060000 NW090000 NW110000: submit/poll, done hook, verify, connect variants.

concurrent in-flight requests (submit + poll, and the done callback), networked
response verification, header_count, the non-blocking start_connect/Connecting
handshake, and connect_by_node_id over a dht. core library, no trust.
"""

from __future__ import annotations

import threading
import time

from nwep import Address, Bootstrap, Client, Dht, Identity, Method, Server, Status


def now_ms() -> int:
    return int(time.monotonic() * 1000)


def now_secs() -> int:
    return int(time.time())


def lo(octet: int, port: int) -> Address:
    return Address.ipv4_mapped(127, 0, 0, octet, port)


def _echo_server(identity=None):
    identity = identity or Identity.generate()

    def handler(req, res):
        return (
            res.header("etag", "v1").ok(req.path.encode())
            if req.path
            else res.not_found()
        )

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


def test_submit_and_poll_many_requests_concurrently() -> None:
    server, identity, stop, thread = _echo_server()
    try:
        with (
            Client.builder()
            .identity(Identity.generate())
            .connect(server.node_id, Address.loopback(server.local_port)) as client
        ):
            # submit several at once, then drive them all to completion.
            ids = [client.submit(Method.READ, f"/r{i}") for i in range(5)]
            results: dict[int, bytes] = {}
            deadline = time.monotonic() + 5
            while len(results) < len(ids) and time.monotonic() < deadline:
                client.tick(now_ms())
                for rid in ids:
                    if rid in results:
                        continue
                    resp = client.poll_request(rid)
                    if resp is not None:
                        with resp:
                            results[rid] = resp.body
                time.sleep(0.003)
            assert len(results) == 5
            assert sorted(results.values()) == [f"/r{i}".encode() for i in range(5)]
    finally:
        stop.set()
        thread.join(timeout=2)
        server.close()
        identity.close()


def test_on_request_done_fires_with_the_response() -> None:
    server, identity, stop, thread = _echo_server()
    try:
        with (
            Client.builder()
            .identity(Identity.generate())
            .connect(server.node_id, Address.loopback(server.local_port)) as client
        ):
            done: dict[int, bytes] = {}

            def hook(request_id, response, error):
                if response is not None:
                    with response:
                        done[request_id] = response.body

            client.on_request_done(hook)
            rid = client.submit(Method.READ, "/hooked")
            deadline = time.monotonic() + 5
            while rid not in done and time.monotonic() < deadline:
                client.tick(now_ms())
                time.sleep(0.003)
            assert done.get(rid) == b"/hooked"
            client.on_request_done(None)  # clearing must not crash.
    finally:
        stop.set()
        thread.join(timeout=2)
        server.close()
        identity.close()


def test_verify_response_and_header_count() -> None:
    server, identity, stop, thread = _echo_server()
    try:
        with (
            Client.builder()
            .identity(Identity.generate())
            .connect(server.node_id, Address.loopback(server.local_port)) as client
        ):
            with client.send(Method.READ, "/doc") as resp:
                assert resp.status == Status.OK
                assert resp.header_count() >= 1  # at least the etag.
                # the response verifies against the connection peer for its path.
                client.verify_response(resp, "/doc", now_secs())
    finally:
        stop.set()
        thread.join(timeout=2)
        server.close()
        identity.close()


def test_start_connect_non_blocking_handshake() -> None:
    server, identity, stop, thread = _echo_server()
    try:
        connecting = (
            Client.builder()
            .identity(Identity.generate())
            .start_connect(server.node_id, Address.loopback(server.local_port))
        )
        # drive the handshake from a loop; poll returns the Client when ready.
        client = None
        deadline = time.monotonic() + 5
        while client is None and time.monotonic() < deadline:
            connecting.tick(now_ms())
            client = connecting.poll()
            time.sleep(0.003)
        assert client is not None
        with client:
            with client.send(Method.READ, "/async-connected") as resp:
                assert resp.body == b"/async-connected"
    finally:
        stop.set()
        thread.join(timeout=2)
        server.close()
        identity.close()


def test_connect_by_node_id_through_a_dht() -> None:
    # a rendezvous + an announcing peer; a fresh client resolves the peer by
    # node_id through its own dht and connects, all in connect_by_node_id.
    r_port, a_port, g_port = 19601, 19602, 19603

    r_id = Identity.generate()
    r_server = Server.builder().identity(r_id).bind(lo(1, r_port)).build()
    r_contact = Bootstrap.of(r_server.node_id, lo(1, r_port))
    r_dht = Dht.attach(r_server, [r_contact])
    r_dht.bootstrap(now_secs())

    a_id = Identity.generate()
    a_server = (
        Server.builder()
        .identity(a_id)
        .bind(lo(2, a_port))
        .on_request(lambda req, res: res.ok(b"found-me"))
        .build()
    )
    a_dht = Dht.attach(a_server, [r_contact])
    a_dht.bootstrap(now_secs())

    g_server = (
        Server.builder().identity(Identity.generate()).bind(lo(3, g_port)).build()
    )
    g_dht = Dht.attach(g_server, [r_contact])
    g_dht.bootstrap(now_secs())

    stop = threading.Event()

    def loop():
        while not stop.is_set():
            for srv, dht, addr in (
                (r_server, r_dht, None),
                (a_server, a_dht, lo(2, a_port)),
                (g_server, g_dht, None),
            ):
                srv.tick(now_ms())
                dht.tick(now_secs())
            a_dht.announce(lo(2, a_port), now_secs())
            time.sleep(0.005)

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()
    try:
        time.sleep(1.0)  # let the announce register.
        client = (
            Client.builder()
            .identity(Identity.generate())
            .connect_by_node_id(a_server.node_id, g_dht, 8000)
        )
        with client:
            with client.send(Method.READ, "/x") as resp:
                assert resp.body == b"found-me"
    finally:
        stop.set()
        thread.join(timeout=3)
        for d in (g_dht, a_dht, r_dht):
            d.close()
        for s in (g_server, a_server, r_server):
            s.close()
