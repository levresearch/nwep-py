"""the managed (L2) happy path, the five minute quickstart.

a fully async server and client, no tick loop, no fileno, no thread in sight. the
runtime owns the loops behind the actor bridge NWG0600: the single-threaded c
handle is pinned to an owner thread and the async surface bridges to it over
asyncio futures.

    python examples/managed.py
"""

from __future__ import annotations

import asyncio

from nwep import Address, Client, Identity, Method, Server, Status


async def main() -> None:
    server = await (
        Server.builder()
        .identity(Identity.generate())
        .bind(Address.loopback(0))
        .on_request(
            lambda req, res: (
                res.ok(b"hi from web/1") if req.path == "/hello" else res.not_found()
            )
        )
        .serve()
    )
    print(f"serving        {server.node_id} on [::1]:{server.local_port}")

    async with await Client.builder().identity(Identity.generate()).connect_async(
        server.node_id, Address.loopback(server.local_port)
    ) as client:
        resp = await client.send(Method.READ, "/hello")
        print(f"read /hello    {resp.status} {resp.body!r}")
        assert resp.status is Status.OK and resp.body == b"hi from web/1"

    await server.shutdown()
    print("shutdown       clean")


if __name__ == "__main__":
    asyncio.run(main())
