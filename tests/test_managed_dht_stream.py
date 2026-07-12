"""managed dht resolve + managed streaming tests NWG0200 NWG0600, fully async.

mirrors the rust managed_dht and managed_stream surfaces: a managed server owns an
attached dht so resolve(node_id) is just an await, and a managed stream pulls a
large body chunk by chunk over its own connection. each test drives an event loop
with asyncio.run (no pytest-asyncio dependency).
"""

from __future__ import annotations

import asyncio
import threading

import pytest

import nwep
from nwep import Address, Bootstrap, Client, Identity, Method, Server, Status


def test_managed_dht_resolve() -> None:
    """a managed dht resolves a node_id another node announced NW110800.

    the announcing node self-bootstraps and announces its address, a second node
    seeded with the first as a contact resolves it by node_id alone. the managed
    dht needs a contact and a real port, so this binds fixed loopback ports.
    """
    port_a, port_b = 29421, 29422

    async def main():
        id_a = Identity.generate()
        self_a = Bootstrap.of(id_a.node_id, Address.loopback(port_a))
        try:
            server_a = await (
                Server.builder()
                .identity(id_a)
                .bind(Address.loopback(port_a))
                .on_request(lambda req, res: res.ok())
                .dht([self_a])
                .announce_as(Address.loopback(port_a))
                .serve()
            )
        except nwep.NwepError as exc:
            pytest.skip(f"port {port_a} may be in use: {exc}")

        id_b = Identity.generate()
        try:
            server_b = await (
                Server.builder()
                .identity(id_b)
                .bind(Address.loopback(port_b))
                .on_request(lambda req, res: res.ok())
                .dht([self_a])
                .serve()
            )
        except nwep.NwepError as exc:
            await server_a.shutdown()
            pytest.skip(f"port {port_b} may be in use: {exc}")

        try:
            addr = await server_b.resolve(id_a.node_id, timeout=5.0)
            assert addr.port == port_a
        finally:
            await server_b.shutdown()
            await server_a.shutdown()

    asyncio.run(main())


def test_resolve_without_dht_raises() -> None:
    """resolve raises a config error when no managed dht was attached."""

    async def main():
        server = await (
            Server.builder()
            .identity(Identity.generate())
            .bind(Address.loopback(0))
            .on_request(lambda req, res: res.ok())
            .serve()
        )
        try:
            with pytest.raises(nwep.ConfigError):
                await server.resolve(server.node_id, timeout=0.2)
        finally:
            await server.shutdown()

    asyncio.run(main())


def test_managed_stream_pulls_body() -> None:
    """the managed AsyncStream pulls a large streamed body and verifies it NW060200.

    a driven server streams a /big body across ticks on its own thread, and the
    managed client stream reads it chunk by chunk to the verified end.
    """
    body = b"nwep-stream-" * 20000  # ~240 KB, larger than one message chunk.

    async def main():
        server_id = Identity.generate()
        opened: "list[tuple[int, int]]" = []
        lock = threading.Lock()

        def handle(req, res):
            if req.path == "/big":
                with lock:
                    opened.append((req.conn_id, req.stream_id))
                return res.stream(
                    "/big", Status.OK, [("content-type", "application/octet-stream")]
                )
            return res.not_found()

        server = (
            Server.builder()
            .identity(server_id)
            .bind(Address.loopback(0))
            .on_request(handle)
            .build()
        )
        port = server.local_port

        stop = threading.Event()

        def pump():
            active: "list[list[int]]" = []  # [conn, stream, sent]
            while not stop.is_set():
                server.tick(_now_ms())
                with lock:
                    while opened:
                        c, s = opened.pop(0)
                        active.append([c, s, 0])
                still = []
                for a in active:
                    blocked = False
                    while a[2] < len(body):
                        n = server.stream_send(a[0], a[1], body[a[2] :])
                        a[2] += n
                        if n == 0:
                            blocked = True
                            break
                    if a[2] < len(body) and blocked:
                        still.append(a)
                    else:
                        server.stream_end(a[0], a[1])
                active = still
                import time

                time.sleep(0.001)
            server.close()

        thread = threading.Thread(target=pump, name="stream-server", daemon=True)
        thread.start()

        try:
            stream = await (
                Client.builder()
                .identity(Identity.generate())
                .stream(Method.READ, "/big", server_id.node_id, Address.loopback(port))
            )
            assert str(stream.status) == "ok" or stream.status == Status.OK
            got = bytearray()
            while True:
                chunk = await stream.recv()
                if chunk is None:
                    break
                got.extend(chunk)
            await stream.aclose()
            assert bytes(got) == body
        finally:
            stop.set()
            thread.join()

    asyncio.run(main())


def _now_ms() -> int:
    import time

    return int(time.monotonic() * 1000)
