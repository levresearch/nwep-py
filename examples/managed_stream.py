"""the managed streaming quickstart, pull a body too large for one message, async.

the client side is the managed AsyncStream (ClientBuilder.stream): it connects on
its own owner thread, opens the stream, and recv() yields the body chunk by chunk
until a verified end (the trailer signature checked against the peer, spec 6.9).
server-side streaming is driven, so a small driven server pushes /big across ticks
on a background thread NWG0600. both halves run in this one process.

    python examples/managed_stream.py
"""

from __future__ import annotations

import asyncio
import threading
import time

from nwep import Address, Client, Identity, Method, Server, Status

BODY = b"nwep-stream-" * 20000  # ~240 KB, larger than one message chunk.


def _now_ms() -> int:
    return int(time.monotonic() * 1000)


def _run_streaming_server(
    server_id: Identity, port_box: list, stop: threading.Event
) -> None:
    """a driven server that streams /big across ticks, on its own thread."""
    opened: list = []
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
    port_box.append(server.local_port)

    active: list = []  # [conn, stream, sent]
    while not stop.is_set():
        server.tick(_now_ms())
        with lock:
            while opened:
                conn, stream = opened.pop(0)
                active.append([conn, stream, 0])
        still = []
        for entry in active:
            blocked = False
            while entry[2] < len(BODY):
                sent = server.stream_send(entry[0], entry[1], BODY[entry[2] :])
                entry[2] += sent
                if sent == 0:
                    blocked = True
                    break
            if entry[2] < len(BODY) and blocked:
                still.append(entry)
            else:
                server.stream_end(entry[0], entry[1])
        active = still
        time.sleep(0.001)
    server.close()


async def main() -> None:
    server_id = Identity.generate()
    port_box: list = []
    stop = threading.Event()
    thread = threading.Thread(
        target=_run_streaming_server, args=(server_id, port_box, stop), daemon=True
    )
    thread.start()
    while not port_box:  # wait for the server to bind and report its port.
        await asyncio.sleep(0.01)
    port = port_box[0]
    print(f"serving        /big ({len(BODY)} bytes) on [::1]:{port}")

    try:
        stream = await (
            Client.builder()
            .identity(Identity.generate())
            .stream(Method.READ, "/big", server_id.node_id, Address.loopback(port))
        )
        print(f"stream open    status {stream.status}")

        received = bytearray()
        chunks = 0
        async with stream:
            while True:
                chunk = await stream.recv()
                if chunk is None:
                    break  # the verified end of the body.
                received.extend(chunk)
                chunks += 1

        print(
            f"pulled         {len(received)} bytes in {chunks} chunks, trailer verified"
        )
        assert bytes(received) == BODY
    finally:
        stop.set()
        thread.join()
    print("shutdown       clean")


if __name__ == "__main__":
    asyncio.run(main())
