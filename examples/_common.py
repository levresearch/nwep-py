"""shared helpers for the examples: a monotonic clock and a backgrounded server.

each example is a self-contained, runnable program (python examples/<name>.py) that
reproduces a sandbox dogfood app's protocol surface over the real quic transport.
these helpers keep the examples focused on the protocol, not the boilerplate of
driving a server loop on a thread.
"""

from __future__ import annotations

import threading
import time
from typing import Callable

from nwep import Server


def now_ms() -> int:
    """returns a monotonic millisecond clock for tick, as the driven layer expects."""
    return int(time.monotonic() * 1000)


def now_secs() -> int:
    """returns the unix-seconds clock the dht and trust layers use."""
    return int(time.time())


class DrivenServer:
    """runs a Server on a background thread, optionally pumping extra work each tick.

    the examples own the loop (the L1 driven model); this just spares each one the
    same thread + tick boilerplate. on_tick, if given, runs once per tick on the
    server thread (for pushing notifications or draining streams).
    """

    def __init__(self, server: Server, on_tick: "Callable[[], None] | None" = None):
        self.server = server
        self.node_id = server.node_id
        self.port = server.local_port
        self._on_tick = on_tick
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        while not self._stop.is_set():
            self.server.tick(now_ms())
            if self._on_tick is not None:
                self._on_tick()
            time.sleep(0.002)

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=3)
        self.server.close()

    def __enter__(self) -> "DrivenServer":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.stop()
