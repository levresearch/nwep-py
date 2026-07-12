"""client is the outbound half of a web/1 node, the driven L1 surface NW070000.

Client opens a connection to a peer and sends requests over it. it is the driven
layer: send() blocks while it drives the exchange, and for an event loop the same
handle exposes fileno() / tick(now) / next_timeout(now) / is_alive(). build one
with the ClientBuilder, which connects (running the handshake) on its terminal:

    with (Client.builder()
            .identity(Identity.generate())
            .connect(server.node_id, Address.loopback(server.local_port))) as client:
        response = client.send(Method.READ, "/hello")
        print(response.status, response.body)
"""

from __future__ import annotations

import traceback
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable, Iterator, Optional, Union

from . import _sys
from . import message as _message
from .address import Address
from .errors import check
from .identity import Identity, NodeId
from .message import HeadersArg, encode_headers
from .wire import Compression, Method, Status

if TYPE_CHECKING:
    from .cache import Cache
    from .dht import Dht
    from .errors import NwepError as Error
    from .runtime import AsyncClient, AsyncStream

# RequestId names an in-flight request submitted with Client.submit NW060000.
RequestId = int

# the c WOULD_BLOCK code: an async request is not ready yet NW130000.
_WOULD_BLOCK = -803

# a request-done callback: (id, response_or_none, error_or_none) -> None.
RequestDoneHook = Callable[[RequestId, "Optional[Response]", "Optional[Error]"], None]

ffi = _sys.ffi
lib = _sys.lib

# token -> Status, for mapping a response's status token to the enum NW080000.
_STATUS_BY_TOKEN = {s.token: s for s in Status}


@dataclass(frozen=True, slots=True)
class ClientMetrics:
    """ClientMetrics is a snapshot of one client's counters NW000017.

    cumulative request counters, two gauges (requests_inflight, alive), and the
    connection's smoothed rtt in microseconds (0 when down).
    """

    requests_inflight: int
    requests_completed: int
    requests_failed: int
    smoothed_rtt_us: int
    alive: bool


# the chunk size client streams read by default.
_STREAM_CHUNK = 65536


class Response:
    """Response is a decoded response received from a peer, owned by the caller NW060000.

    it owns the underlying message and frees it on close, so use it as a context
    manager or read what you need and let it fall out of scope. it exposes the
    status, headers, and body.
    """

    __slots__ = ("_msg", "_closed")

    def __init__(self, msg: "_sys.CData"):
        self._msg = msg
        self._closed = False

    @property
    def status(self) -> Optional[Status]:
        """returns the response status NW080000, or None for an unknown token."""
        token = _message.status_token(self._msg)
        return _STATUS_BY_TOKEN.get(token) if token is not None else None

    def header(self, name: str) -> Optional[str]:
        """returns the value of a response header, or None when absent NW060300."""
        self._check_open()
        return _message.header(self._msg, name)

    def headers(self) -> Iterator[tuple[str, str]]:
        """iterates every response header in wire order NW060300."""
        self._check_open()
        return _message.headers(self._msg)

    def header_count(self) -> int:
        """returns the number of headers on this response NW060300."""
        self._check_open()
        return _message.header_count(self._msg)

    @property
    def body(self) -> bytes:
        """returns the response body, empty when there is none NW060000."""
        self._check_open()
        return _message.body(self._msg)

    def _raw_message(self) -> "_sys.CData":
        """lends the raw c message pointer, for handing to a shared cache."""
        self._check_open()
        return self._msg

    def close(self) -> None:
        """frees the underlying message. idempotent, also done on context exit."""
        if not self._closed:
            lib.nwep_message_free(self._msg)
            self._closed = True

    def _check_open(self) -> None:
        if self._closed:
            raise ValueError("response is closed (its message was freed)")

    def __enter__(self) -> "Response":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def __repr__(self) -> str:
        if self._closed:
            return "Response(closed)"
        return f"Response(status={self.status})"


class Client:
    """Client is a connection to a peer whose loop the caller drives NW070000.

    send() is blocking; for an event loop, register fileno() with a poller and
    drive tick(now_ms) on each wakeup, using next_timeout(now_ms) as the timeout
    and is_alive() to notice a dropped connection. close() (or leaving its
    with-block) tears the connection down. drive one Client from one thread only.
    """

    __slots__ = ("_handle", "_closed", "_cache", "_done_cb")

    def __init__(self, handle: "_sys.CData"):
        self._handle = handle
        self._closed = False
        self._cache: "Optional[Cache]" = (
            None  # keeps an attached cache alive (it is borrowed).
        )
        self._done_cb = None  # keeps the request-done cffi callback alive.

    @staticmethod
    def builder() -> "ClientBuilder":
        """starts a ClientBuilder, the way every client is constructed NWG0300."""
        return ClientBuilder()

    def send(
        self,
        method: Union[Method, int],
        path: str,
        body: bytes = b"",
        headers: Optional[HeadersArg] = None,
    ) -> Response:
        """sends one request and blocks until the response arrives NW060000.

        drives the exchange internally (the blocking convenience over tick). pass
        headers as a dict or a sequence of (name, value) pairs.

        returns the decoded Response.
        raises a NetworkError on a transport failure, ProtocolError on a malformed
        request, or the NW130000 error the peer reports.
        """
        out = ffi.new("nwep_message **")
        # the header cdata and its backing strings must outlive the send call,
        # so they are held in locals here for the whole call.
        header_array, _keep = encode_headers(headers)
        check(
            lib.nwep_client_send(
                self._handle,
                int(method),
                path.encode("utf-8"),
                header_array,
                _body_ptr(body),
                len(body),
                out,
            )
        )
        return Response(out[0])

    def fileno(self) -> int:
        """returns the udp socket fd, for registering with a poller NWG0200.

        the socket is owned by the client; do not close it, drive all i/o through
        tick. having fileno() lets a selector or asyncio loop watch the client.
        """
        return int(lib.nwep_client_fd(self._handle))

    def tick(self, now_ms: int) -> None:
        """advances the client once: datagrams, quic timers, in-flight requests.

        call on every socket readiness event and timer expiry. now_ms is a
        monotonic millisecond clock.

        raises a NetworkError on a fatal transport fault.
        """
        check(lib.nwep_client_tick(self._handle, now_ms))

    def next_timeout(self, now_ms: int) -> Optional[int]:
        """returns ms until tick must next run, or None when nothing is pending."""
        timeout = lib.nwep_client_next_timeout_ms(self._handle, now_ms)
        return None if timeout < 0 else timeout

    def is_alive(self) -> bool:
        """returns whether the connection is still usable NW090900.

        False once the connection has terminally closed (idle timeout, peer close,
        or a fatal quic error); poll it to drive reconnection.
        """
        return lib.nwep_client_is_alive(self._handle) == 1

    def metrics(self) -> ClientMetrics:
        """returns a snapshot of this client's counters and gauges NW000017.

        returns the ClientMetrics.
        raises InternalError on a null handle.
        """
        out = ffi.new("nwep_client_metrics *")
        check(lib.nwep_client_metrics_get(self._handle, out))
        return ClientMetrics(
            requests_inflight=int(out.requests_inflight),
            requests_completed=int(out.requests_completed),
            requests_failed=int(out.requests_failed),
            smoothed_rtt_us=int(out.smoothed_rtt_us),
            alive=out.alive == 1,
        )

    @property
    def compression(self) -> Compression:
        """returns the codec this connection negotiated in the handshake NW000017."""
        code = lib.nwep_client_compression(self._handle)
        return Compression(code) if code in (0, 1) else Compression.UNKNOWN

    @property
    def peer_pubkey(self) -> bytes:
        """returns the connected peer's 32-byte ed25519 public key NW090000.

        the key a streamed response or a signed response is verified against
        (Stream.verify, Response signatures, NW060900).

        returns the 32-byte public key.
        raises an error from the transport when the peer key is unavailable.
        """
        out = ffi.new("uint8_t[]", _sys.PUBKEY_SIZE)
        check(lib.nwep_client_peer_pubkey(self._handle, out))
        return bytes(ffi.buffer(out, _sys.PUBKEY_SIZE))

    def set_cache(self, cache: "Optional[Cache]") -> None:
        """attaches a cache to serve repeat reads, or detaches it with None NW060700.

        the cache is borrowed and must outlive the client, so this keeps a
        reference to it; it is not freed when the client closes. pass None to
        detach.

        raises an error from the transport on failure.
        """
        check(
            lib.nwep_client_set_cache(
                self._handle, cache.raw if cache is not None else ffi.NULL
            )
        )
        self._cache = cache

    def poll_notify(self) -> Optional[Response]:
        """pumps the connection once and returns the next queued NOTIFY push NW060200.

        call repeatedly to drain all pending pushes. read the event with
        response.header(":event"). returns the NOTIFY as a Response, or None when
        none is pending.
        """
        msg = lib.nwep_client_poll_notify(self._handle)
        return Response(msg) if msg != ffi.NULL else None

    def submit(
        self,
        method: Union[Method, int],
        path: str,
        body: bytes = b"",
        headers: Optional[HeadersArg] = None,
    ) -> RequestId:
        """submits a request without blocking and returns its id NW060000.

        the non-blocking counterpart of send: it returns at once with an id; drive
        completion with tick + poll_request, or register on_request_done. lets many
        requests be in flight on one connection at once.

        returns the in-flight request's RequestId.
        raises ProtoMaxStreams at the connection's concurrent-stream limit, and a
        transport or ProtocolError otherwise.
        """
        header_array, _keep = encode_headers(headers)
        out = ffi.new("nwep_request_id *")
        check(
            lib.nwep_client_request_submit(
                self._handle,
                int(method),
                path.encode("utf-8"),
                header_array,
                _body_ptr(body),
                len(body),
                out,
            )
        )
        return int(out[0])

    def poll_request(self, request_id: RequestId) -> Optional[Response]:
        """polls a submitted request for its response NW060000.

        returns the Response once the request is complete (the id is then retired),
        or None while it is still in flight.
        raises the transport or NW130000 error the request produced.
        """
        out = ffi.new("nwep_message **")
        rc = lib.nwep_client_request_poll(self._handle, request_id, out)
        if rc == 0:
            return Response(out[0])
        if rc == _WOULD_BLOCK:
            return None
        check(rc)
        return None

    def cancel_request(self, request_id: RequestId) -> None:
        """cancels an in-flight request, retiring its id NW060000."""
        lib.nwep_client_request_cancel(self._handle, request_id)

    def on_request_done(self, hook: Optional[RequestDoneHook]) -> None:
        """registers a callback fired when a submitted request completes NW060000.

        the hook runs inside tick with (id, response, error): on success response
        is a Response (and error None), on failure response is None and error is
        the NW130000 Error. pass None to clear it. the hook must not block or call
        tick reentrantly; an exception in it is reported and swallowed, never
        unwound into c NWG0900.
        """
        if hook is None:
            lib.nwep_client_set_request_done(self._handle, ffi.NULL, ffi.NULL)
            self._done_cb = None
            return

        @ffi.callback("nwep_request_done_fn")
        def trampoline(_client, request_id, status, resp, _ud):
            try:
                if status == 0:
                    hook(int(request_id), Response(resp), None)
                else:
                    from .errors import from_code

                    hook(int(request_id), None, from_code(status))
            except Exception:  # no python exception may unwind into c NWG0900.
                traceback.print_exc()

        self._done_cb = trampoline
        lib.nwep_client_set_request_done(self._handle, trampoline, ffi.NULL)

    def verify_response(self, response: Response, path: str, now_secs: int = 0) -> None:
        """verifies a response's signature against the connection peer NW060900.

        pulls the origin pubkey from the connection so the wrong key cannot be
        passed; path is required since the signed form binds it. pass now_secs to
        also enforce freshness, or 0 to skip the freshness check.

        raises CryptoError when the signature is invalid, IdentityError when not
        yet connected.
        """
        check(
            lib.nwep_client_verify_response(
                self._handle, response._raw_message(), path.encode("utf-8"), now_secs
            )
        )

    def open_stream(
        self,
        method: Union[Method, int],
        path: str,
        headers: Optional[HeadersArg] = None,
    ) -> "Stream":
        """opens a streamed response for a body too large for one message NW060200.

        sends a body-less request and returns a Stream to pull the response from
        chunk by chunk. the way to receive a body over NWEP_MAX_MESSAGE_SIZE or of
        unknown length.

        returns the open Stream.
        raises a NetworkError on a transport failure, ProtocolError on a malformed
        request.
        """
        header_array, _keep = encode_headers(headers)
        out = ffi.new("uint64_t *")
        check(
            lib.nwep_client_open_stream(
                self._handle, int(method), path.encode("utf-8"), header_array, out
            )
        )
        return Stream(self, int(out[0]))

    @property
    def raw(self) -> "_sys.CData":
        """returns the raw c nwep_client pointer, the escape hatch to sys NWG0200."""
        return self._handle

    def close(self) -> None:
        """closes the connection and frees the handle. idempotent."""
        if not self._closed:
            lib.nwep_client_close(self._handle)
            self._closed = True
            self._done_cb = None

    def __enter__(self) -> "Client":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def __repr__(self) -> str:
        state = "closed" if self._closed else ("alive" if self.is_alive() else "dead")
        return f"Client({state})"


class Connecting:
    """Connecting is a handshake in progress from a non-blocking connect NW000017.

    returned by ClientBuilder.start_connect. drive it with a tick loop: call tick()
    each wakeup, then poll()  -  None while still handshaking, the connected Client
    once done. dropping it before completion closes the underlying handle.
    """

    __slots__ = ("_handle", "_done")

    def __init__(self, handle: "_sys.CData"):
        self._handle = handle
        self._done = False  # true once poll() handed the Client off or it failed.

    def fileno(self) -> int:
        """returns the udp socket fd, to register with a poller during the handshake."""
        return int(lib.nwep_client_fd(self._handle))

    def tick(self, now_ms: int) -> None:
        """advances the handshake; call before poll on each wakeup NW090000."""
        check(lib.nwep_client_tick(self._handle, now_ms))

    def poll(self) -> Optional[Client]:
        """polls the handshake, returning the Client once it completes NW000017.

        tick first, then poll: returns None while still handshaking, or the
        connected Client when done (ownership transfers, so poll once more is not
        needed).
        raises a transport error when the handshake fails (the handle is closed).
        """
        if self._done:
            raise ValueError("this Connecting has already completed")
        rc = lib.nwep_client_connect_poll(self._handle)
        if rc == 1:
            self._done = True
            client = Client(self._handle)
            return client
        if rc == 0:
            return None
        # rc < 0: the handshake failed and the handle is already closed by c.
        self._done = True
        check(rc)
        return None

    def close(self) -> None:
        """closes the handshaking handle if it never completed. idempotent."""
        if not self._done:
            lib.nwep_client_close(self._handle)
            self._done = True

    def __enter__(self) -> "Connecting":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


class ClientBuilder:
    """ClientBuilder constructs a Client in prose NWG0300.

    set the identity, then connect(target_node_id, addr) which runs the handshake
    and returns a connected Client. connect() is the driven terminal (it blocks on
    the handshake); a managed connect_async() that owns the loop is layered on
    later NWG0200.
    """

    __slots__ = ("_identity",)

    def __init__(self):
        self._identity: Optional[Identity] = None

    def identity(self, identity: Identity) -> "ClientBuilder":
        """sets the identity the client proves ownership of in the handshake NW090000."""
        self._identity = identity
        return self

    def connect(self, target_node_id: NodeId, address: Address) -> Client:
        """connects to a peer, running the handshake, and returns a Client NW090000.

        verifies the peer's node_id against target_node_id during the handshake
        NW040200, so a connected client is talking to the intended node. blocks
        until the handshake completes.

        returns the connected Client.
        raises ConfigError when the identity is unset, NetworkError when the
        connection fails, and a CryptoError when the peer's identity does not match.
        """
        identity = self._require_identity()
        out = ffi.new("nwep_client **")
        check(
            lib.nwep_client_connect(
                out, identity._keypair(), target_node_id._raw(), address._raw()
            )
        )
        return Client(out[0])

    def connect_fd(self, target_node_id: NodeId, address: Address, fd: int) -> Client:
        """connects over a caller-owned udp socket, adopting it NW000017.

        like connect, but adopts an already-created AF_INET6 udp socket (ownership
        transfers to the client, which closes it). blocks until connected.

        returns the connected Client.
        raises ConfigError when the identity is unset, and a transport error on
        failure.
        """
        identity = self._require_identity()
        out = ffi.new("nwep_client **")
        check(
            lib.nwep_client_connect_fd(
                out,
                identity._keypair(),
                target_node_id._raw(),
                address._raw(),
                fd,
            )
        )
        return Client(out[0])

    def connect_by_node_id(
        self, target_node_id: NodeId, dht: "Dht", lookup_timeout_ms: int
    ) -> Client:
        """resolves a node_id through a dht and connects to it NW110800.

        runs a find_value lookup over the dht's shared socket for up to
        lookup_timeout_ms, then connects to the resolved address. the dht must be
        attached to a server. blocks for the lookup and the handshake.

        returns the connected Client.
        raises ConfigError when the identity is unset, IdentityNotFound when the
        lookup times out, and a transport error on a connect failure.
        """
        identity = self._require_identity()
        out = ffi.new("nwep_client **")
        check(
            lib.nwep_client_connect_by_nodeid(
                out,
                identity._keypair(),
                target_node_id._raw(),
                dht.raw,
                lookup_timeout_ms,
            )
        )
        return Client(out[0])

    def start_connect(self, target_node_id: NodeId, address: Address) -> "Connecting":
        """starts a non-blocking connect, returning a Connecting to poll NW000017.

        the driven async connect: it returns at once with a handshaking handle you
        drive with tick + Connecting.poll, so the handshake folds into your own
        event loop rather than blocking. the managed counterpart is connect_async.

        returns the Connecting in progress.
        raises ConfigError when the identity is unset, and a transport error on a
        failure to start.
        """
        identity = self._require_identity()
        out = ffi.new("nwep_client **")
        check(
            lib.nwep_client_connect_async(
                out, identity._keypair(), target_node_id._raw(), address._raw()
            )
        )
        return Connecting(out[0])

    def start_connect_fd(
        self, target_node_id: NodeId, address: Address, fd: int
    ) -> "Connecting":
        """starts a non-blocking connect over a caller-owned socket NW000017.

        like start_connect, but adopts an already-created udp socket. returns the
        Connecting to port.
        raises ConfigError when the identity is unset, and a transport error on a
        failure to start.
        """
        identity = self._require_identity()
        out = ffi.new("nwep_client **")
        check(
            lib.nwep_client_connect_fd_async(
                out,
                identity._keypair(),
                target_node_id._raw(),
                address._raw(),
                fd,
            )
        )
        return Connecting(out[0])

    def _require_identity(self) -> Identity:
        if self._identity is None:
            from .errors import ConfigMissing  # type: ignore[attr-defined]

            raise ConfigMissing("client builder is missing the identity")
        return self._identity

    async def connect_async(
        self, target_node_id: NodeId, address: Address
    ) -> "AsyncClient":
        """connects on a runtime thread and returns an async client NWG0200 NWG0600.

        the managed terminal: the runtime owns the loop. the blocking handshake
        runs on a dedicated owner thread, and this coroutine resolves once
        connected. mirrors connect() but send() is awaitable.

        returns the connected AsyncClient.
        raises ConfigError when the identity is unset, and a transport error when
        the connection fails.
        """
        if self._identity is None:
            from .errors import ConfigMissing  # type: ignore[attr-defined]

            raise ConfigMissing("client builder is missing the identity")
        from . import runtime

        return await runtime._connect_async(self, target_node_id, address)

    async def stream(
        self,
        method: Union[Method, int],
        path: str,
        target_node_id: NodeId,
        address: Address,
    ) -> "AsyncStream":
        """opens a streamed response over a dedicated connection, fully async NW060200.

        the managed terminal for receiving a body too large for one message. it
        connects on its own owner thread, opens the stream, reads the metadata
        frame, and returns an AsyncStream whose recv() yields the body chunk by
        chunk. the connection is dedicated to this stream and closes on aclose().

        returns the open AsyncStream, its status and headers already read.
        raises ConfigError when the identity is unset, and a transport error when
        the connection or stream cannot open.
        """
        if self._identity is None:
            from .errors import ConfigMissing  # type: ignore[attr-defined]

            raise ConfigMissing("client builder is missing the identity")
        from . import runtime

        return await runtime._stream(self, method, path, target_node_id, address)


class Stream:
    """Stream is a streamed response being received chunk by chunk NW060200.

    opened with Client.open_stream. read the leading frame with response() for the
    status and headers, then loop recv() until it reports the end, and verify() the
    trailer signature. close() releases it (also done on context exit). the calls
    block while they drive the exchange, like Client.send.
    """

    __slots__ = ("_client", "_id", "_closed")

    def __init__(self, client: "Client", stream_id: int):
        self._client = client
        self._id = stream_id
        self._closed = False

    @property
    def stream_id(self) -> int:
        """returns the quic stream id this response rides on NW060200."""
        return self._id

    def response(self) -> Response:
        """reads the leading response frame, its status and headers NW060200.

        blocks until it arrives. read it before the body chunks.

        returns the Response carrying the status and headers (no body yet).
        raises a transport error on failure.
        """
        self._check_open()
        out = ffi.new("nwep_message **")
        check(lib.nwep_client_stream_response(self._client.raw, self._id, out))
        return Response(out[0])

    def recv(self, size: int = _STREAM_CHUNK) -> tuple[bytes, bool]:
        """reads the next body chunk, blocking until some arrives or it ends NW060200.

        returns (chunk, ended): the bytes read (up to size) and whether the stream
        has ended (FIN seen and all bytes delivered). stop once ended is True.
        raises a transport error on failure.
        """
        self._check_open()
        buf = ffi.new("uint8_t[]", size)
        out_len = ffi.new("size_t *")
        out_ended = ffi.new("int *")
        check(
            lib.nwep_client_stream_recv(
                self._client.raw, self._id, buf, size, out_len, out_ended
            )
        )
        chunk = bytes(ffi.buffer(buf, out_len[0])) if out_len[0] else b""
        return chunk, out_ended[0] == 1

    def verify(self, pubkey: bytes) -> None:
        """verifies the fully-received stream's trailer signature NW060900.

        call after recv reports the end. the path is the one open_stream was given.

        raises CryptoError when the signature is missing, invalid, or the stream
        was truncated; ValueError on a wrong-length key.
        """
        self._check_open()
        if len(pubkey) != _sys.PUBKEY_SIZE:
            raise ValueError(
                f"pubkey must be {_sys.PUBKEY_SIZE} bytes, got {len(pubkey)}"
            )
        check(lib.nwep_client_stream_verify(self._client.raw, self._id, pubkey))

    def close(self) -> None:
        """releases the stream's bookkeeping. idempotent, also done on context exit."""
        if not self._closed and not self._client._closed:
            lib.nwep_client_stream_close(self._client.raw, self._id)
        self._closed = True

    def _check_open(self) -> None:
        if self._closed:
            raise ValueError("stream is closed")

    def __enter__(self) -> "Stream":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def __repr__(self) -> str:
        return f"Stream(id={self._id}{', closed' if self._closed else ''})"


def verify_response(
    response: Response, pubkey: bytes, path: str, now_secs: int = 0
) -> None:
    """verifies a response's signature against an explicit origin key NW060900.

    the standalone check, for a response obtained without a live connection to its
    origin (for example one served from a shared cache): the caller supplies the
    origin pubkey. when the response came over a connection, Client.verify_response
    pulls the key from the connection so the wrong one cannot be passed. path is
    required since the signed form binds it; pass now_secs to also enforce
    freshness, or 0 to skip it.

    raises CryptoError when the signature is invalid, ValueError on a wrong-length
    key.
    """
    if len(pubkey) != _sys.PUBKEY_SIZE:
        raise ValueError(f"pubkey must be {_sys.PUBKEY_SIZE} bytes, got {len(pubkey)}")
    check(
        lib.nwep_response_verify(
            response._raw_message(), pubkey, path.encode("utf-8"), now_secs
        )
    )


def _body_ptr(body: bytes) -> "_sys.CData":
    """returns the c body pointer, NULL for an empty body (the header's contract)."""
    return body if body else ffi.NULL
