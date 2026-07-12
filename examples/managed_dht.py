"""the managed dht quickstart, resolve a peer by node_id alone, fully async.

a server whose runtime owns an attached dht, so resolve(node_id) is just an await,
no tick loop. one node announces itself into the dht, and a second node seeded with
the first as a bootstrap contact resolves it back to an address NW110800. for a
self-contained demo both nodes run in this one process on fixed loopback ports.

    python examples/managed_dht.py
"""

from __future__ import annotations

import asyncio

from nwep import Address, Bootstrap, Identity, Server

PORT_A, PORT_B = 29431, 29432


async def main() -> None:
    # the announcing node: self-bootstraps (its only contact is itself) and
    # announces its own address into the dht.
    id_a = Identity.generate()
    self_a = Bootstrap.of(id_a.node_id, Address.loopback(PORT_A))
    announcer = await (
        Server.builder()
        .identity(id_a)
        .bind(Address.loopback(PORT_A))
        .on_request(lambda req, res: res.ok())
        .dht([self_a])
        .announce_as(Address.loopback(PORT_A))
        .serve()
    )
    print(f"announcer      {id_a.node_id} on [::1]:{PORT_A}")

    # the resolver: its runtime owns a dht seeded with the announcer as a contact,
    # so resolve(node_id) is a single await.
    resolver = await (
        Server.builder()
        .identity(Identity.generate())
        .bind(Address.loopback(PORT_B))
        .on_request(lambda req, res: res.ok())
        .dht([self_a])
        .serve()
    )

    address = await resolver.resolve(id_a.node_id, timeout=5.0)
    print(f"resolved       {id_a.node_id} -> [::1]:{address.port}")
    assert address.port == PORT_A

    metrics = await resolver.dht_metrics()
    print(
        f"dht traffic    {metrics.datagrams_sent} sent, {metrics.datagrams_received} received"
    )

    await resolver.shutdown()
    await announcer.shutdown()
    print("shutdown       clean")


if __name__ == "__main__":
    asyncio.run(main())
