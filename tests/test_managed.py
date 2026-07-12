"""managed asyncio layer tests NWG0200 NWG0600: serve() + connect_async(), fully async.

the L2 on-ramp: no tick loop, no fileno, no thread in the test. the runtime owns
the loop on an owner thread and bridges to asyncio. each test drives an event loop
with asyncio.run (no pytest-asyncio dependency).
"""

from __future__ import annotations

import asyncio

import pytest

import nwep
from nwep import (
    Address,
    AsyncClient,
    Client,
    Identity,
    Method,
    RunningServer,
    Server,
    Status,
)


def _hello(req, res):
    if req.path == "/hello":
        return res.ok(b"hi from web/1")
    if req.path == "/echo":
        return res.ok(req.body)
    return res.not_found()


async def _serve_hello() -> RunningServer:
    return await (
        Server.builder()
        .identity(Identity.generate())
        .bind(Address.loopback(0))
        .on_request(_hello)
        .serve()
    )


async def _connect(server: RunningServer) -> AsyncClient:
    return await (
        Client.builder()
        .identity(Identity.generate())
        .connect_async(server.node_id, Address.loopback(server.local_port))
    )


def test_managed_round_trip() -> None:
    async def main():
        server = await _serve_hello()
        assert server.local_port > 0
        client = await _connect(server)
        try:
            with await client.send(Method.READ, "/hello") as resp:
                assert resp.status == Status.OK
                assert resp.body == b"hi from web/1"
            with await client.send(Method.READ, "/missing") as resp:
                assert resp.status == Status.NOT_FOUND
        finally:
            await client.aclose()
            await server.shutdown()

    asyncio.run(main())


def test_managed_async_context_managers() -> None:
    async def main():
        async with await _serve_hello() as server:
            async with await _connect(server) as client:
                with await client.send(Method.WRITE, "/echo", body=b"payload") as resp:
                    assert resp.body == b"payload"

    asyncio.run(main())


def test_managed_many_requests_complete() -> None:
    # the owner thread serves sends in order; awaiting many still completes all.
    async def main():
        async with await _serve_hello() as server:
            async with await _connect(server) as client:
                results = await asyncio.gather(
                    *(
                        client.send(Method.WRITE, "/echo", body=str(i).encode())
                        for i in range(8)
                    )
                )
                bodies = sorted(int(r.body) for r in results)
                for r in results:
                    r.close()
                assert bodies == list(range(8))

    asyncio.run(main())


def test_send_after_close_raises_network_closed() -> None:
    async def main():
        server = await _serve_hello()
        client = await _connect(server)
        await client.aclose()
        with pytest.raises(nwep.NetworkError):
            await client.send(Method.READ, "/hello")
        await server.shutdown()

    asyncio.run(main())


def test_connect_async_to_a_dead_address_raises() -> None:
    async def main():
        # nothing is listening here, so the handshake fails and the awaiter sees it.
        bogus = Identity.generate().node_id
        with pytest.raises(nwep.NwepError):
            await (
                Client.builder()
                .identity(Identity.generate())
                .connect_async(bogus, Address.loopback(1))
            )

    asyncio.run(main())


def test_shutdown_is_clean_and_idempotent() -> None:
    async def main():
        server = await _serve_hello()
        client = await _connect(server)
        await client.aclose()
        await client.aclose()  # idempotent: a second close is a no-op.
        await server.shutdown()

    asyncio.run(main())
