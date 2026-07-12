"""nwdrop, a decentralized resumable file drop (mirrors sandbox/005-nwdrop).

the protocol's no-dns headline: a node is dialed by node_id alone, resolved through
the dht, then a body is pulled with resumable byte ranges. a rendezvous node, a
sender that announces a file, and a getter that resolves + downloads all run in one
process. each node binds a distinct loopback ip so they do not share one dht
per-source-ip budget.

    python examples/nwdrop.py
"""

from __future__ import annotations

import threading
import time

from _common import now_ms, now_secs
from nwep import Address, Bootstrap, Client, Dht, Identity, Method, RangeKind, Server

FILE = bytes((i * 13 + 5) % 256 for i in range(4096))  # the "file" served at /file.
R_PORT, A_PORT, G_PORT = 19701, 19702, 19703


def lo(octet: int, port: int) -> Address:
    return Address.ipv4_mapped(127, 0, 0, octet, port)


def file_handler(req, res):
    if req.path != "/file":
        return res.not_found()
    # serve the whole file, or a byte range for a resumable download.
    outcome = req.range(len(FILE))
    if outcome.kind is RangeKind.RANGES:
        return res.partial(FILE, outcome.ranges, "application/octet-stream")
    return res.ok(FILE)


def main() -> None:
    # the rendezvous: self-bootstraps and routes.
    r_id = Identity.generate()
    r_server = Server.builder().identity(r_id).bind(lo(1, R_PORT)).build()
    r_contact = Bootstrap.of(r_server.node_id, lo(1, R_PORT))
    r_dht = Dht.attach(r_server, [r_contact])
    r_dht.bootstrap(now_secs())

    # the sender: answers /file and announces its address.
    a_id = Identity.generate()
    a_node = a_id.node_id
    a_server = (
        Server.builder()
        .identity(a_id)
        .bind(lo(2, A_PORT))
        .on_request(file_handler)
        .build()
    )
    a_dht = Dht.attach(a_server, [r_contact])
    a_dht.bootstrap(now_secs())

    # the getter: resolves the sender by node_id and downloads.
    g_server = (
        Server.builder().identity(Identity.generate()).bind(lo(3, G_PORT)).build()
    )
    g_dht = Dht.attach(g_server, [r_contact])
    g_dht.bootstrap(now_secs())

    stop = threading.Event()

    def loop():
        while not stop.is_set():
            for srv, dht in ((r_server, r_dht), (a_server, a_dht), (g_server, g_dht)):
                srv.tick(now_ms())
                dht.tick(now_secs())
            a_dht.announce(lo(2, A_PORT), now_secs())
            time.sleep(0.005)

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()
    try:
        print(f"sender announced  {a_node}")
        time.sleep(1.0)  # let the announce register with the rendezvous.

        # resolve the sender by node_id alone (no dns, no address up front).
        g_dht.start_lookup(a_node, now_secs())
        record = None
        for _ in range(300):
            record = g_dht.lookup_result(a_node)
            if record is not None:
                break
            time.sleep(0.01)
        assert record is not None, "the dht did not resolve the sender"
        print(f"resolved by node  -> [::ffff:127.0.0.2]:{record.address.port}")

        client = (
            Client.builder()
            .identity(Identity.generate())
            .connect(a_node, record.address)
        )
        with client:
            # a resumable download: pull the file in two ranged halves.
            half = len(FILE) // 2
            with client.send(
                Method.READ, "/file", headers={"range": f"bytes=0-{half - 1}"}
            ) as p1:
                part1 = p1.body
            with client.send(
                Method.READ, "/file", headers={"range": f"bytes={half}-{len(FILE) - 1}"}
            ) as p2:
                part2 = p2.body
            downloaded = part1 + part2
            print(
                f"downloaded        {len(part1)} + {len(part2)} = {len(downloaded)} bytes (resumable)"
            )
            assert downloaded == FILE
            print("integrity         the reassembled file matches")
    finally:
        stop.set()
        thread.join(timeout=3)
        for d in (g_dht, a_dht, r_dht):
            d.close()
        for s in (g_server, a_server, r_server):
            s.close()


if __name__ == "__main__":
    main()
