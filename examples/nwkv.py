"""nwkv, a key-value service with notify pushes (mirrors sandbox/000-nwkv).

a server stores values under paths via write, serves them via read, removes them
via delete, and pushes a notify on each change. a client drives the whole
lifecycle in one process and prints what it observes.

    python examples/nwkv.py
"""

from __future__ import annotations

import threading

from _common import DrivenServer, now_ms
from nwep import Address, Client, Identity, Method, Server, Status

store: dict[str, bytes] = {}
to_notify: list[int] = []
lock = threading.Lock()


def handler(req, res):
    path = req.path or ""
    with lock:
        if req.method is Method.WRITE:
            store[path] = req.body
            to_notify.append(req.conn_id)  # the loop pushes a notify after tick.
            return res.status(Status.CREATED)
        if req.method is Method.DELETE:
            return (
                res.status(Status.NO_CONTENT)
                if store.pop(path, None) is not None
                else res.not_found()
            )
        value = store.get(path)
        return res.ok(value) if value is not None else res.not_found()


def main() -> None:
    srv = (
        Server.builder()
        .identity(Identity.generate())
        .bind(Address.loopback(0))
        .on_request(handler)
        .build()
    )

    def push():
        # a handler holds no Server, so notify runs from the loop.
        with lock:
            pending = list(to_notify)
            to_notify.clear()
        for conn in pending:
            srv.notify(conn, "kv.changed")

    with DrivenServer(srv, on_tick=push) as node:
        client = (
            Client.builder()
            .identity(Identity.generate())
            .connect(node.node_id, Address.loopback(node.port))
        )
        with client:
            # write a value, then watch the change notification arrive.
            w = client.send(Method.WRITE, "/greeting", b"hello kv")
            print(f"write /greeting   {w.status}")
            w.close()

            for _ in range(1000):
                client.tick(now_ms())
                pushed = client.poll_notify()
                if pushed is not None:
                    print(f"notify            {pushed.header(':event')}")
                    pushed.close()
                    break

            # read it back, delete it, then confirm it is gone.
            with client.send(Method.READ, "/greeting") as r:
                print(f"read /greeting    {r.status} {r.body!r}")
            with client.send(Method.DELETE, "/greeting") as d:
                print(f"delete /greeting  {d.status}")
            with client.send(Method.READ, "/greeting") as g:
                print(f"read /greeting    {g.status} (gone)")


if __name__ == "__main__":
    main()
