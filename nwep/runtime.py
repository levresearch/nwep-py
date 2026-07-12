"""runtime is the managed asyncio layer that owns the event loop for you NWG0200 NWG0600.

the c handles are single threaded and caller driven, so they cannot be awaited
across asyncio's loop directly. instead each managed handle is pinned to one
dedicated owner thread that runs the real tick and poll loop, and the async
surface bridges to it by message passing (the actor bridge, NWG0600): a request
crosses to the owner thread, and its result crosses back into the asyncio loop via
loop.call_soon_threadsafe. asyncio hosts only the futures, never the handle.

built entirely on the driven api (ServerBuilder.build, Client), so it adds the
async on-ramp without a parallel implementation and the driven layer stays
reachable underneath (no cliffs, NWG0200). reach it through the builder's async
terminals: ServerBuilder.serve() and ClientBuilder.connect_async().
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import queue
import select
import threading
import time
from typing import TYPE_CHECKING, Optional

from .errors import ConfigMissing, IdentityNotFound, NetworkClosed  # type: ignore[attr-defined]
from .identity import NodeId

if TYPE_CHECKING:
    from .address import Address
    from .client import ClientBuilder, Response
    from .dht import DhtMetrics
    from .server import ServerBuilder

# the owner loop caps its socket wait so a shutdown request is noticed within one
# interval even when no transport timer is pending (seconds).
_POLL_CAP_S = 0.1


def _now_ms() -> int:
    """returns a monotonic millisecond clock for tick, as the driven layer expects."""
    return int(time.monotonic() * 1000)


def _now_secs() -> int:
    """returns a unix-seconds clock for the dht, as its layer expects NW110000."""
    return int(time.time())


class _Resolve:
    """a resolve-by-node_id request for the server owner thread, with its future."""

    __slots__ = ("target", "timeout", "future", "loop")

    def __init__(self, target, timeout, future, loop):
        self.target = target
        self.timeout = timeout
        self.future = future
        self.loop = loop


class _DhtMetrics:
    """a dht-metrics scrape request for the server owner thread, with its future."""

    __slots__ = ("future", "loop")

    def __init__(self, future, loop):
        self.future = future
        self.loop = loop


def _resolve_blocking(server, dht, target, timeout_s: float):
    """resolves target through the dht, pumping the loop on the owner thread NW110800.

    checks the local store first, then starts a lookup and pumps the server and dht
    until the record resolves or timeout elapses. blocks the owner loop for the
    duration, exactly as the c blocking resolve does, the connection stays alive
    because this keeps ticking it.

    returns the resolved Address.
    raises IdentityNotFound when the lookup times out with no record.
    """
    record = dht.lookup_result(target)
    if record is not None:
        return record.address
    dht.start_lookup(target, _now_secs())
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        server.tick(_now_ms())
        secs = _now_secs()
        dht.tick(secs)
        record = dht.lookup_result(target)
        if record is not None:
            return record.address
        _wait_readable(server.fileno(), _cap(dht.next_timeout(secs)))
    raise IdentityNotFound("dht lookup timed out with no record")


def _wait_readable(fd: int, timeout_s: float) -> None:
    """waits up to timeout_s for a socket fd to become readable, best effort.

    a wakeup, a timeout, or an interrupted select all simply return; the next tick
    reconciles state either way.
    """
    try:
        select.select([fd], [], [], timeout_s)
    except (OSError, ValueError):
        # a closing fd can race select; the loop's stop check handles it.
        pass


# managed server NWG0200


class RunningServer:
    """RunningServer is a Server whose loop the runtime owns on a thread NWG0200 NWG0600.

    the server runs on its own owner thread, dispatching to the handler, until
    shutdown() is awaited. the handler runs synchronously on that thread inside
    tick, so it must not block. obtained from ServerBuilder.serve().
    """

    __slots__ = ("_node_id", "_port", "_thread", "_stop", "_commands")

    def __init__(
        self,
        node_id: NodeId,
        port: int,
        thread: threading.Thread,
        stop: threading.Event,
        commands: "Optional[queue.SimpleQueue]" = None,
    ):
        self._node_id = node_id
        self._port = port
        self._thread = thread
        self._stop = stop
        # the command queue exists only when a managed dht is attached, it carries
        # resolve and metrics requests to the owner thread where the dht lives.
        self._commands = commands

    @property
    def node_id(self) -> NodeId:
        """returns the server's own node_id, the one clients dial NW040200."""
        return self._node_id

    @property
    def local_port(self) -> int:
        """returns the udp port the server bound, resolving a bind to port 0."""
        return self._port

    async def resolve(self, target: NodeId, timeout: float = 5.0) -> Address:
        """resolves a peer's node_id to an address through the managed dht NW110800.

        runs an iterative lookup on the owner thread while the loop ticks the dht,
        so this coroutine resolves without blocking the asyncio loop. requires the
        server was built with ServerBuilder.dht.

        returns the resolved Address.
        raises ConfigError when no managed dht is attached, and IdentityError when
        the lookup times out with no record.
        """
        if self._commands is None:
            raise ConfigMissing(
                "no managed dht is attached, build with ServerBuilder.dht"
            )
        loop = asyncio.get_running_loop()
        future: "asyncio.Future[Address]" = loop.create_future()
        self._commands.put(_Resolve(target, timeout, future, loop))
        return await future

    async def dht_metrics(self) -> "DhtMetrics":
        """returns a snapshot of the managed dht's counters, scraped on the owner.

        raises ConfigError when no managed dht is attached.
        """
        if self._commands is None:
            raise ConfigMissing(
                "no managed dht is attached, build with ServerBuilder.dht"
            )
        loop = asyncio.get_running_loop()
        future: "asyncio.Future[DhtMetrics]" = loop.create_future()
        self._commands.put(_DhtMetrics(future, loop))
        return await future

    async def shutdown(self) -> None:
        """stops the server and waits for its owner thread to finish.

        signals the owner loop to exit and joins it off the asyncio loop, so the
        socket is closed by the time this returns without blocking other tasks.
        """
        self._stop.set()
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._thread.join)

    async def __aenter__(self) -> "RunningServer":
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.shutdown()


async def _serve(builder: "ServerBuilder") -> RunningServer:
    """builds the server and runs its loop on a dedicated thread NWG0200 NWG0600.

    the managed terminal of ServerBuilder. the server is built on the owner thread
    (the handle never crosses a boundary), then driven there with a real poll until
    the RunningServer is shut down. the on_request handler runs on that thread.

    returns the RunningServer once it is bound and listening.
    raises ConfigError for an unset identity or bind address, and any bind error.
    """
    ready: "concurrent.futures.Future[tuple[NodeId, int]]" = concurrent.futures.Future()
    stop = threading.Event()
    has_dht = builder._dht_contacts is not None
    commands: "queue.SimpleQueue" = queue.SimpleQueue()

    def owner() -> None:
        try:
            server = builder.build()
        except BaseException as exc:  # report the build failure to the awaiter.
            ready.set_exception(exc)
            return
        # the dht borrows the server, so both live on this owner thread NW110000.
        dht = None
        try:
            if has_dht:
                from .dht import Dht  # local import avoids a runtime import cycle.

                dht = Dht.attach(server, builder._dht_contacts, builder._dht_seq)
                dht.bootstrap(_now_secs())
        except BaseException as exc:
            server.close()
            ready.set_exception(exc)
            return
        try:
            ready.set_result((server.node_id, server.local_port))
        except concurrent.futures.InvalidStateError:
            server.close()  # the awaiter was cancelled before we bound.
            return
        last_announce = 0
        try:
            fd = server.fileno()
            while not stop.is_set():
                _service_server_commands(commands, server, dht)
                server.tick(_now_ms())
                if dht is not None:
                    now = _now_secs()
                    dht.tick(now)
                    if builder._announce is not None and now - last_announce >= 60:
                        dht.announce(builder._announce, now)
                        last_announce = now
                timeout = server.next_timeout(_now_ms())
                _wait_readable(fd, _cap(timeout))
        finally:
            # the dht borrows the server's socket, so it must be closed first or
            # its later teardown is a use-after-free on the freed server NW110000.
            if dht is not None:
                dht.close()
            server.close()  # the handle is built, driven, and closed all here.

    thread = threading.Thread(target=owner, name="nwep-server", daemon=True)
    thread.start()
    node_id, port = await asyncio.wrap_future(ready)
    return RunningServer(node_id, port, thread, stop, commands if has_dht else None)


def _service_server_commands(commands: "queue.SimpleQueue", server, dht) -> None:
    """runs every queued resolve or metrics command on the owner thread NWG0600."""
    while True:
        try:
            cmd = commands.get_nowait()
        except queue.Empty:
            return
        if isinstance(cmd, _Resolve):
            try:
                addr = _resolve_blocking(server, dht, cmd.target, cmd.timeout)
                cmd.loop.call_soon_threadsafe(_resolve, cmd.future, addr)
            except BaseException as exc:
                cmd.loop.call_soon_threadsafe(_reject, cmd.future, exc)
        elif isinstance(cmd, _DhtMetrics):
            try:
                metrics = dht.metrics()
                cmd.loop.call_soon_threadsafe(_resolve, cmd.future, metrics)
            except BaseException as exc:
                cmd.loop.call_soon_threadsafe(_reject, cmd.future, exc)


# managed client NWG0200 NWG0600


class _Send:
    """one send for the client owner thread to run, with its asyncio future."""

    __slots__ = ("method", "path", "body", "headers", "future", "loop")

    def __init__(self, method, path, body, headers, future, loop):
        self.method = method
        self.path = path
        self.body = body
        self.headers = headers
        self.future = future
        self.loop = loop


# the sentinel a shutdown enqueues to break the owner loop.
_STOP = object()


class AsyncClient:
    """AsyncClient is a Client driven on its own thread, with an async api NWG0600.

    each send is forwarded to the owner thread, which runs the blocking request and
    returns the response into the asyncio loop, so requests on one connection are
    served in order. obtained from ClientBuilder.connect_async(); close it with
    aclose() or an async with block.
    """

    __slots__ = ("_queue", "_thread", "_closed")

    def __init__(self, command_queue: "queue.SimpleQueue", thread: threading.Thread):
        self._queue = command_queue
        self._thread = thread
        self._closed = False

    async def send(self, method, path, body: bytes = b"", headers=None) -> "Response":
        """sends one request and awaits the response, without blocking the loop NW060000.

        the request crosses to the owner thread, which runs the blocking exchange
        and delivers the response back into this loop. pass headers as a dict or a
        sequence of (name, value) pairs.

        returns the decoded Response.
        raises NetworkClosed when the client has been closed, and any transport or
        spec-13 error the request itself produces.
        """
        if self._closed:
            raise NetworkClosed("client is closed")
        loop = asyncio.get_running_loop()
        future: "asyncio.Future[Response]" = loop.create_future()
        self._queue.put(_Send(method, path, body, headers, future, loop))
        return await future

    async def aclose(self) -> None:
        """closes the connection and stops the owner thread. idempotent."""
        if self._closed:
            return
        self._closed = True
        self._queue.put(_STOP)
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._thread.join)

    async def __aenter__(self) -> "AsyncClient":
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()


def _resolve(future: "asyncio.Future", result) -> None:
    """sets a future's result from the owner thread, unless it was cancelled."""
    if not future.cancelled():
        future.set_result(result)


def _reject(future: "asyncio.Future", exc: BaseException) -> None:
    """sets a future's exception from the owner thread, unless it was cancelled."""
    if not future.cancelled():
        future.set_exception(exc)


async def _connect_async(
    builder: "ClientBuilder", target_node_id: NodeId, address
) -> AsyncClient:
    """opens a connection on a dedicated thread and returns an async client NWG0600.

    the managed counterpart of ClientBuilder.connect. the blocking handshake runs
    on the owner thread, and this coroutine resolves once it is connected. the
    owner thread then serves each send in order until the client is closed.

    returns the connected AsyncClient.
    raises ConfigError for an unset identity, and a transport error when the
    connection fails.
    """
    ready: "concurrent.futures.Future[None]" = concurrent.futures.Future()
    commands: "queue.SimpleQueue" = queue.SimpleQueue()

    def owner() -> None:
        try:
            client = builder.connect(target_node_id, address)
        except BaseException as exc:
            ready.set_exception(exc)
            return
        try:
            ready.set_result(None)
        except concurrent.futures.InvalidStateError:
            client.close()
            return
        try:
            while True:
                try:
                    cmd = commands.get(timeout=_POLL_CAP_S)
                except queue.Empty:
                    client.tick(_now_ms())  # keep the connection alive while idle.
                    continue
                if cmd is _STOP:
                    break
                try:
                    response = client.send(cmd.method, cmd.path, cmd.body, cmd.headers)
                    cmd.loop.call_soon_threadsafe(_resolve, cmd.future, response)
                except BaseException as exc:
                    cmd.loop.call_soon_threadsafe(_reject, cmd.future, exc)
        finally:
            # fail any sends still queued behind the shutdown, then close.
            _drain_pending(commands)
            client.close()

    thread = threading.Thread(target=owner, name="nwep-client", daemon=True)
    thread.start()
    await asyncio.wrap_future(ready)
    return AsyncClient(commands, thread)


def _drain_pending(commands: "queue.SimpleQueue") -> None:
    """fails every send left in the queue with NetworkClosed, on shutdown."""
    while True:
        try:
            cmd = commands.get_nowait()
        except queue.Empty:
            return
        if cmd is _STOP:
            continue
        cmd.loop.call_soon_threadsafe(
            _reject, cmd.future, NetworkClosed("client is closing")
        )


def _cap(timeout_ms: Optional[int]) -> float:
    """folds a next-timeout in ms into a capped select wait in seconds."""
    if timeout_ms is None:
        return _POLL_CAP_S
    return min(timeout_ms / 1000.0, _POLL_CAP_S)


# managed streaming NWG0200 NWG0600

# the end marker the stream owner thread enqueues when the body completes.
_STREAM_END = object()


class AsyncStream:
    """AsyncStream is a streamed response body pulled chunk by chunk NWG0600.

    a streamed body is too large for one message, and the c stream recv blocks, so
    it cannot share the concurrent request loop. an AsyncStream runs on its own
    owner thread over its own dedicated connection: the owner opens the stream,
    reads the metadata frame, then loops recv pushing each chunk onto a queue
    recv() awaits, and verifies the trailer at the end NW060900. obtained from
    ClientBuilder.stream.
    """

    __slots__ = ("_status", "_headers", "_items", "_thread", "_stop")

    def __init__(self, status, headers, items, thread, stop):
        self._status = status
        self._headers = headers
        self._items = items
        self._thread = thread
        self._stop = stop

    @property
    def status(self):
        """returns the streamed response status, from its leading frame NW080000."""
        return self._status

    def header(self, name: str) -> Optional[str]:
        """returns a response header value, or None when absent NW060300."""
        for n, v in self._headers:
            if n == name:
                return v
        return None

    def headers(self):
        """returns the streamed response headers in wire order NW060300."""
        return list(self._headers)

    async def recv(self) -> Optional[bytes]:
        """awaits the next body chunk, or None at the verified end NW060200.

        the owner thread reads the body and delivers each chunk here. once recv
        returns None the body is complete and its trailer signature has verified
        against the peer NW060900, an authentic, whole body.

        returns a chunk while streaming, or None at the verified end.
        raises a transport error mid-stream, or CryptoError when the trailer
        signature does not verify.
        """
        loop = asyncio.get_running_loop()
        item = await loop.run_in_executor(None, self._items.get)
        if item is _STREAM_END:
            return None
        if isinstance(item, BaseException):
            raise item
        return item

    async def aclose(self) -> None:
        """stops the owner thread and tears down the dedicated connection."""
        self._stop.set()
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._thread.join)

    async def __aenter__(self) -> "AsyncStream":
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()


async def _stream(
    builder: "ClientBuilder", method, path: str, target_node_id: NodeId, address
) -> AsyncStream:
    """opens a streamed response over a dedicated connection, fully async NW060200.

    the managed terminal for receiving a body too large for one message. it
    connects on its own owner thread, opens the stream, reads the metadata frame,
    and returns an AsyncStream whose recv yields the body chunk by chunk. the
    connection is dedicated to this stream and closes on aclose.

    returns the open AsyncStream, its status and headers already read.
    raises ConfigError for an unset identity, and a transport error opening it.
    """
    ready: "concurrent.futures.Future[tuple]" = concurrent.futures.Future()
    items: "queue.SimpleQueue" = queue.SimpleQueue()
    stop = threading.Event()

    def owner() -> None:
        try:
            client = builder.connect(target_node_id, address)
        except BaseException as exc:
            ready.set_exception(exc)
            return
        try:
            stream = client.open_stream(method, path)
            meta = stream.response()
            status, headers = meta.status, list(meta.headers())
        except BaseException as exc:
            client.close()
            ready.set_exception(exc)
            return
        try:
            ready.set_result((status, headers))
        except concurrent.futures.InvalidStateError:
            stream.close()
            client.close()
            return
        try:
            peer = client.peer_pubkey
            while not stop.is_set():
                chunk, ended = stream.recv()
                if chunk:
                    items.put(chunk)
                if ended:
                    # the trailer must verify for the body to count as whole NW060900.
                    try:
                        stream.verify(peer)
                    except BaseException as exc:
                        items.put(exc)
                        return
                    items.put(_STREAM_END)
                    return
        except BaseException as exc:
            items.put(exc)
        finally:
            stream.close()
            client.close()

    thread = threading.Thread(target=owner, name="nwep-stream", daemon=True)
    thread.start()
    status, headers = await asyncio.wrap_future(ready)
    return AsyncStream(status, headers, items, thread, stop)
