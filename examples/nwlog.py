"""nwlog, a transparency-log node (mirrors sandbox/002-nwlog).

a real in-memory merkle log runs behind a quic server via the log-server router; a
client builds its own signed key-binding entry and submits it over write /log/entry,
which the server verifies and appends (the on-append hook fires). the entry decodes
back to the same fields, and read /log/root returns the new size + root. this is the
producer + log-node story; verifying others' entries is the trust layer.

    python examples/nwlog.py
"""

from __future__ import annotations

import hashlib

from _common import DrivenServer, now_secs
from nwep import Address, Client, Identity, KeyBinding, Log, LogServer, Method, Server

appended: list[int] = []


def main() -> None:
    server_identity = Identity.generate()
    log = Log()
    log_server = LogServer(server_identity, log)
    log_server.on_append(lambda entry, index: appended.append(index))

    def handler(req, res):
        reply = log_server.dispatch(req, res, now_secs())
        return reply if reply is not None else res.not_found()

    srv = (
        Server.builder()
        .identity(server_identity)
        .bind(Address.loopback(0))
        .on_request(handler)
        .build()
    )
    with DrivenServer(srv) as node:
        # a submitter publishes its own key binding.
        with Identity.generate() as submitter, Identity.generate() as recovery:
            commitment = hashlib.sha256(recovery.public_key).digest()
            entry = KeyBinding.create(submitter, commitment, now_secs())
            print(f"key binding     {len(entry)} bytes, node {submitter.node_id}")

            client = (
                Client.builder()
                .identity(submitter)
                .connect(node.node_id, Address.loopback(node.port))
            )
            with client:
                with client.send(Method.WRITE, "/log/entry", body=entry) as resp:
                    print(
                        f"write /log/entry  {resp.status}, on_append fired for index {appended}"
                    )

                # the entry decodes back to the same fields (producer + auditor).
                decoded = KeyBinding.decode(entry)
                assert decoded.node_id == submitter.node_id
                print(f"decode entry      node_id matches, ts {decoded.timestamp}")

                # read /log/root: [8B size][32B merkle root] NW121000.
                with client.send(Method.READ, "/log/root") as root:
                    size = int.from_bytes(root.body[:8], "big")
                    print(
                        f"read /log/root    size {size}, root {root.body[8:].hex()[:16]}..."
                    )

        log_server.close()
        log.close()
    server_identity.close()


if __name__ == "__main__":
    main()
