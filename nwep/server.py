"""server is the listening half of a web/1 node, the driven L1 surface NW070000.

Server owns a bound udp socket, runs the quic handshake per connection, and
dispatches each decoded request to a handler. it is the driven layer: the caller
owns the event loop, advancing it with tick(now_ms) and waking on fileno() until
next_timeout(now_ms). a managed runtime that owns the loop is layered on top
later NWG0200.

a handler is a callable (Request, Responder) -> Reply. it runs synchronously
inside tick on the tick thread and must not block, must not call tick or close
(reentrant tick corrupts connection state), and must answer through the responder
exactly once. build a server with the ServerBuilder:

    def handle(req, res):
        if req.path == "/hello":
            return res.ok(b"hi")
        return res.not_found()

    with (Server.builder()
            .identity(Identity.generate())
            .bind(Address.loopback(0))
            .on_request(handle)
            .build()) as server:
        ...  # drive server.tick(now_ms()) from your loop
"""

from __future__ import annotations

import sys
import traceback
from dataclasses import dataclass, field
from enum import IntEnum
from typing import TYPE_CHECKING, Callable, Iterator, Optional, Sequence

if TYPE_CHECKING:
    from .client import Response
    from .errors import NwepError as Error
    from .runtime import RunningServer

from . import _sys
from . import message as _message
from .address import Address
from .errors import check
from .identity import Identity, NodeId
from .wire import Compression, Method, Status


def _to_compression(code: int) -> Compression:
    """maps a c compression code to the Compression enum, UNKNOWN for anything else."""
    return Compression(code) if code in (0, 1) else Compression.UNKNOWN


@dataclass(frozen=True, slots=True)
class ServerMetrics:
    """ServerMetrics is a snapshot of one reactor's counters NW000017.

    cumulative counters plus three gauges (connections_active, parked_active,
    load). read it from the tick thread; in a reuseport pool each reactor owns
    its own counters.
    """

    connections_active: int
    connections_accepted: int
    connections_refused: int
    connections_closed: int
    bytes_received: int
    bytes_sent: int
    datagrams_received: int
    datagrams_sent: int
    requests_dispatched: int
    requests_shed: int
    parked_active: int
    load: int


ffi = _sys.ffi
lib = _sys.lib

# the c handler return sentinel for an out-of-band (deferred) answer NW060900.
_DEFER = 1

# the c request-range outcome codes NW060800.
_RANGE_OK = 0
_RANGE_NONE = 1
_RANGE_UNSATISFIABLE = 2

# the most satisfiable ranges a single request resolves to NW060800.
_MAX_RANGES = 16

# token -> Method, for reading a request's :method pseudo-header NW050000.
_METHOD_BY_TOKEN = {m.token: m for m in Method}


@dataclass(frozen=True, slots=True)
class ByteRange:
    """ByteRange is one inclusive byte range [start, end] of a resource NW060800."""

    start: int
    end: int


class RangeKind(IntEnum):
    """RangeKind is how a request's range header resolved against a resource NW060800."""

    FULL = 0  # no range, or one ignored by if-range: serve the whole body.
    UNSATISFIABLE = 1  # a valid range selecting no bytes: answer range-not-satisfiable.
    RANGES = 2  # satisfiable ranges: answer partial-content.


@dataclass(frozen=True, slots=True)
class RangeOutcome:
    """RangeOutcome is the result of resolving a request's range header NW060800.

    .kind says which of the three cases held; .ranges holds the satisfiable ranges
    when kind is RANGES (empty otherwise). feed .ranges to Responder.partial.
    """

    kind: RangeKind
    ranges: tuple[ByteRange, ...] = field(default_factory=tuple)


Handler = Callable[["Request", "Responder"], "Reply"]


class Request:
    """Request is the decoded request handed to a handler, borrowed for the call.

    it exposes the request method, path, headers, body, and the connection it
    arrived on. the borrowed strings live only for the handler call, so copy
    anything kept past it (the accessors already return owned python values).
    """

    __slots__ = ("_msg", "_server", "_conn", "_stream")

    def __init__(self, msg: "_sys.CData", server: "_sys.CData", conn: int, stream: int):
        self._msg = msg
        self._server = server
        self._conn = conn
        self._stream = stream

    @property
    def conn_id(self) -> int:
        """returns the id of the connection this request arrived on."""
        return self._conn

    @property
    def stream_id(self) -> int:
        """returns the id of the quic stream this request arrived on NW060200."""
        return self._stream

    @property
    def method(self) -> Optional[Method]:
        """returns the request method, the :method pseudo-header NW050000.

        returns the Method, or None for an unknown verb.
        """
        token = self.header(":method")
        return _METHOD_BY_TOKEN.get(token) if token is not None else None

    @property
    def path(self) -> Optional[str]:
        """returns the request path, the :path pseudo-header NW060200."""
        return self.header(":path")

    def header(self, name: str) -> Optional[str]:
        """returns the value of a header, or None when it is absent NW060300."""
        return _message.header(self._msg, name)

    def headers(self) -> Iterator[tuple[str, str]]:
        """iterates every request header in wire order NW060300."""
        return _message.headers(self._msg)

    @property
    def body(self) -> bytes:
        """returns the request body, empty when there is none NW060000."""
        return _message.body(self._msg)

    def is_fresh(self, etag: str) -> bool:
        """returns whether the request's if-none-match matches etag NW060700.

        a true result means a conditional read or head can be answered with
        Responder.not_modified instead of resending the body. matches `*` or any
        etag in the comma-separated header. false for an unconditional request.
        """
        return lib.nwep_request_is_fresh(self._msg, etag.encode("utf-8")) != 0

    def range(self, total_len: int, etag: Optional[str] = None) -> RangeOutcome:
        """resolves the request's range header against a resource NW060800.

        parses suffix (-N) and open (N-) forms and clamps to total_len. when etag
        is given and the request's if-range does not match it, the range is
        ignored (kind FULL) so a resumed transfer never mixes versions. feed a
        RANGES outcome's ranges to Responder.partial.

        returns the RangeOutcome.
        raises an error from the transport on a null argument.
        """
        etag_c = etag.encode("utf-8") if etag is not None else ffi.NULL
        out = ffi.new("nwep_range[]", _MAX_RANGES)
        count = ffi.new("size_t *")
        rc = check(
            lib.nwep_request_range(
                self._msg, total_len, etag_c, out, _MAX_RANGES, count
            )
        )
        if rc == _RANGE_OK:
            ranges = tuple(
                ByteRange(int(out[i].start), int(out[i].end)) for i in range(count[0])
            )
            return RangeOutcome(RangeKind.RANGES, ranges)
        if rc == _RANGE_UNSATISFIABLE:
            return RangeOutcome(RangeKind.UNSATISFIABLE)
        return RangeOutcome(RangeKind.FULL)

    @property
    def compression(self) -> Compression:
        """returns the codec this request's connection negotiated NW000017."""
        return _to_compression(
            lib.nwep_server_conn_compression(self._server, self._conn)
        )

    def _raw_message(self) -> "_sys.CData":
        """lends the raw c message pointer, for a sub-router like the log server."""
        return self._msg

    @property
    def peer_node_id(self) -> NodeId:
        """returns the authenticated peer node_id of this connection NW090000.

        returns the peer's NodeId.
        raises IdentityError for an unknown connection.
        """
        out = ffi.new("nwep_node_id *")
        check(lib.nwep_server_get_peer_nodeid(self._server, self._conn, out))
        return NodeId(bytes(ffi.buffer(out.bytes, _sys.NODEID_SIZE)))


class Reply:
    """Reply is the token a handler returns to prove it answered NWG0600.

    a handler obtains one only by calling a Responder terminal (ok, status,
    not_found, error, or defer), so returning a Reply is evidence the request was
    answered exactly once. it carries no data the caller needs to read.
    """

    __slots__ = ("deferred",)

    def __init__(self, deferred: bool = False):
        self.deferred = deferred


class Responder:
    """Responder builds a handler's reply, used exactly once NW060000 NW080000.

    chain header() to add response headers, then call one terminal (ok, status,
    not_found, error, or defer) which encodes the reply and returns a Reply. a
    second terminal call is a bug and raises.
    """

    __slots__ = ("_buf", "_server", "_conn", "_stream", "_used")

    def __init__(self, buf: "_sys.CData", server: "_sys.CData", conn: int, stream: int):
        self._buf = buf
        self._server = server
        self._conn = conn
        self._stream = stream
        self._used = False

    def header(self, name: str, value: str) -> "Responder":
        """adds a header to the response being built, chainable NW060300.

        returns this responder so calls chain before a terminal.
        raises ProtocolError for an invalid header.
        """
        check(
            lib.nwep_response_header(
                self._buf, name.encode("utf-8"), value.encode("utf-8")
            )
        )
        return self

    def ok(self, body: bytes = b"") -> Reply:
        """answers with status ok and an optional body NW080000.

        returns the Reply proving the request was answered.
        raises InternalError on an encode failure.
        """
        self._claim()
        check(lib.nwep_response_ok(self._buf, _body_ptr(body), len(body)))
        return Reply()

    def status(self, status: "Status | str", body: bytes = b"") -> Reply:
        """answers with a given status token and an optional body NW080000.

        accepts a Status or its raw token string. returns the Reply.
        raises ProtocolError for an unknown status token, InternalError on encode.
        """
        self._claim()
        token = str(status).encode("utf-8")
        check(lib.nwep_response_status(self._buf, token, _body_ptr(body), len(body)))
        return Reply()

    def created(self, body: bytes = b"") -> Reply:
        """answers with status created NW080000."""
        return self.status(Status.CREATED, body)

    def accepted(self, body: bytes = b"") -> Reply:
        """answers with status accepted NW080000."""
        return self.status(Status.ACCEPTED, body)

    def no_content(self) -> Reply:
        """answers with status no-content and no body NW080000."""
        return self.status(Status.NO_CONTENT)

    def moved(self, location: str) -> Reply:
        """answers with moved; sets the location header to the new web:// URI NW080000."""
        return self.header("location", location).status(Status.MOVED)

    def bad_request(self, body: bytes = b"") -> Reply:
        """answers with status bad-request NW080000."""
        return self.status(Status.BAD_REQUEST, body)

    def unauthorized(self, body: bytes = b"") -> Reply:
        """answers with status unauthorized NW080000."""
        return self.status(Status.UNAUTHORIZED, body)

    def forbidden(self, body: bytes = b"") -> Reply:
        """answers with status forbidden NW080000."""
        return self.status(Status.FORBIDDEN, body)

    def not_found(self, body: bytes = b"") -> Reply:
        """answers with status not-found NW080000."""
        return self.status(Status.NOT_FOUND, body)

    def not_allowed(self) -> Reply:
        """answers with not-allowed  -  the method is not permitted on this resource NW080000."""
        return self.status(Status.NOT_ALLOWED)

    def conflict(self, body: bytes = b"") -> Reply:
        """answers with status conflict NW080000."""
        return self.status(Status.CONFLICT, body)

    def gone(self) -> Reply:
        """answers with gone  -  the resource is permanently removed NW080000."""
        return self.status(Status.GONE)

    def too_large(self) -> Reply:
        """answers with too-large  -  the request body exceeded the server limit NW080000."""
        return self.status(Status.TOO_LARGE)

    def precondition_failed(self) -> Reply:
        """answers with precondition-failed  -  a conditional header did not hold NW080000."""
        return self.status(Status.PRECONDITION_FAILED)

    def rate_limited(self, retry_after: str) -> Reply:
        """answers with rate-limited; retry_after is seconds until the client may retry NW080000."""
        return self.header("retry-after", retry_after).status(Status.RATE_LIMITED)

    def error(self, body: bytes = b"") -> Reply:
        """answers with status error NW080000."""
        return self.status(Status.ERROR, body)

    def unavailable(self) -> Reply:
        """answers with unavailable and no body NW080000."""
        return self.status(Status.UNAVAILABLE)

    def timeout(self) -> Reply:
        """answers with timeout  -  the server took too long to process the request NW080000."""
        return self.status(Status.TIMEOUT)

    def not_implemented(self) -> Reply:
        """answers with not-implemented  -  the method or feature is not supported NW080000."""
        return self.status(Status.NOT_IMPLEMENTED)

    def not_modified(self, etag: str) -> Reply:
        """answers with not-modified and an empty body NW060700.

        the answer to a conditional read or head whose if-none-match matched (see
        Request.is_fresh), so the body is not resent.

        returns the Reply.
        raises InternalError on an encode failure.
        """
        self._claim()
        check(lib.nwep_response_not_modified(self._buf, etag.encode("utf-8")))
        return Reply()

    def partial(
        self, body: bytes, ranges: Sequence[ByteRange], content_type: str
    ) -> Reply:
        """answers with partial-content for one or more byte ranges NW060800.

        body is the FULL resource; ranges come from Request.range. one range sends
        the sub-range with a content-range header, multiple send a
        multipart/byteranges body.

        returns the Reply.
        raises ValueError when ranges is empty, InternalError on an encode failure.
        """
        if not ranges:
            raise ValueError(
                "partial needs at least one range; use ok() for the full body"
            )
        self._claim()
        arr = ffi.new("nwep_range[]", len(ranges))
        for i, r in enumerate(ranges):
            arr[i].start = r.start
            arr[i].end = r.end
        check(
            lib.nwep_response_partial(
                self._buf,
                _body_ptr(body),
                len(body),
                arr,
                len(ranges),
                content_type.encode("utf-8"),
            )
        )
        return Reply()

    def range_not_satisfiable(self, total_len: int) -> Reply:
        """answers with range-not-satisfiable when a range selected no bytes NW060800.

        carries content-range: bytes */total. pairs with a RangeOutcome of kind
        UNSATISFIABLE.

        returns the Reply.
        raises InternalError on an encode failure.
        """
        self._claim()
        check(lib.nwep_response_range_not_satisfiable(self._buf, total_len))
        return Reply()

    def relay(self, origin: "Response") -> Reply:
        """relays an origin response verbatim, preserving its signature NW060900.

        emits origin's status, headers, and body WITHOUT re-signing, so a proxy
        serving a cached origin response on a synchronous hit keeps the origin's
        end-to-end signature  -  the client verifies against the origin node, not the
        proxy. the deferred counterpart is Server.relay.

        returns the Reply.
        raises ProtocolError when origin has no status, InternalError on encode.
        """
        self._claim()
        check(lib.nwep_response_relay(self._buf, origin._raw_message()))
        return Reply()

    def blit(self, frame: bytes) -> Reply:
        """writes a captured wire frame verbatim as the response NW000017.

        no re-encode or re-sign: the fast path for a hot resource. the frame must
        be for this connection's codec (see Request.compression) and still within
        its signature-ts + max-age. capture a frame with capture().

        returns the Reply.
        raises InternalError on a null or unusable frame.
        """
        self._claim()
        check(lib.nwep_response_blit(self._buf, frame, len(frame)))
        return Reply()

    def capture(self) -> bytes:
        """returns the encoded wire frame of the response just built, for caching.

        call after a terminal (ok, relay, ...) has built the response; it reads the
        frame out so a frame cache can blit() it back verbatim on later hits with
        no re-encode or re-sign NW000017. does not itself answer the
        request. key the cache by (path, Request.compression), since a frame is
        codec-specific.

        returns the encoded frame bytes.
        raises RuntimeError when no response has been built yet to capture.
        """
        if not self._used:
            raise RuntimeError(
                "capture() needs a response built first (call ok/relay/... before it)"
            )
        out_len = ffi.new("size_t *", 0)
        check(lib.nwep_response_capture(self._buf, ffi.NULL, 0, out_len))
        size = out_len[0]
        out = ffi.new("uint8_t[]", size)
        out_len[0] = size
        check(lib.nwep_response_capture(self._buf, out, size, out_len))
        return bytes(ffi.buffer(out, out_len[0]))

    def defer(self) -> Reply:
        """defers the answer to be delivered later, out of band NW060900.

        keeps the (conn_id, stream_id) open and writes nothing now; the
        application answers later with Server.respond from its loop. use it when
        the reply depends on a backend fetch you do not want to block the loop on.

        returns the Reply marking this request deferred.
        """
        self._claim()
        return Reply(deferred=True)

    def stream(
        self,
        path: str,
        status: "Status | str",
        headers: Optional["_message.HeadersArg"] = None,
    ) -> Reply:
        """switches the response into streamed mode for a large body NW060200.

        begins a streamed response with the leading status and headers; the body
        is then sent from the loop with Server.stream_send and finished with
        Server.stream_end. path is the request path, bound into the response
        signature, so pass the path being answered.

        returns the Reply; the handler returns it, then streams the body itself.
        raises ProtocolError on an invalid status or header.
        """
        self._claim()
        header_array, _keep = _message.encode_headers(headers)
        check(
            lib.nwep_server_begin_stream(
                self._server,
                self._conn,
                self._stream,
                path.encode("utf-8"),
                str(status).encode("utf-8"),
                header_array,
            )
        )
        return Reply()

    def _claim(self) -> None:
        if self._used:
            raise RuntimeError(
                "the request was already answered (responder used twice)"
            )
        self._used = True


class Server:
    """Server is a listening web/1 node whose loop the caller drives NW070000.

    own the event loop: register fileno() with a poller, and on each wakeup or
    timer call tick(now_ms), using next_timeout(now_ms) as the poll timeout. the
    handler fires synchronously inside tick. close() (or leaving its with-block)
    shuts it down. drive a single Server from one thread only.
    """

    __slots__ = ("_handle", "_handler_cb", "_closed")

    def __init__(self, handle: "_sys.CData"):
        self._handle = handle
        self._handler_cb: object = None  # keeps the cffi callback alive
        self._closed = False

    @staticmethod
    def builder() -> "ServerBuilder":
        """starts a ServerBuilder, the way every server is constructed NWG0300."""
        return ServerBuilder()

    @property
    def node_id(self) -> NodeId:
        """returns the server's own node_id, the one clients dial NW040200."""
        out = ffi.new("nwep_node_id *")
        check(lib.nwep_server_local_nodeid(self._handle, out))
        return NodeId(bytes(ffi.buffer(out.bytes, _sys.NODEID_SIZE)))

    @property
    def local_port(self) -> int:
        """returns the udp port actually bound, resolving a bind to port 0."""
        return lib.nwep_server_local_port(self._handle)

    def fileno(self) -> int:
        """returns the udp socket fd, for registering with a poller NWG0200.

        the socket is non-blocking and owned by the server; do not close it, drive
        all i/o through tick. having fileno() lets a selector or asyncio loop watch
        the server directly.
        """
        return int(lib.nwep_server_fd(self._handle))

    def tick(self, now_ms: int) -> None:
        """advances every state machine once, the heart of the loop NW070000.

        reads inbound datagrams, runs the handshake, fires the handler for each
        completed request, and flushes outbound datagrams. call on every socket
        readiness event and every timer expiry. now_ms is a monotonic millisecond
        clock.

        raises a NetworkError or ProtocolError on a fatal transport fault.
        """
        check(lib.nwep_server_tick(self._handle, now_ms))

    def next_timeout(self, now_ms: int) -> Optional[int]:
        """returns ms until tick must next run for a pending timer, or None.

        pass the result straight as the poll timeout; None means nothing is
        pending, 0 means a timer is already due.
        """
        timeout = lib.nwep_server_next_timeout_ms(self._handle, now_ms)
        return None if timeout < 0 else timeout

    def respond(
        self, conn_id: int, stream_id: int, status: "Status | str", body: bytes = b""
    ) -> None:
        """delivers a deferred response from the loop, signed by the server NW060900.

        answers a request a handler returned defer() for. relies on the (conn_id,
        stream_id) still being parked (the connection is open).

        raises AppError (app-not-found) when the request is no longer parked.
        """
        token = str(status).encode("utf-8")
        check(
            lib.nwep_server_respond(
                self._handle, conn_id, stream_id, token, _body_ptr(body), len(body)
            )
        )

    def respond_header(
        self, conn_id: int, stream_id: int, name: str, value: str
    ) -> None:
        """attaches a header to the next respond() on a parked request NW060300."""
        check(
            lib.nwep_server_respond_header(
                self._handle,
                conn_id,
                stream_id,
                name.encode("utf-8"),
                value.encode("utf-8"),
            )
        )

    def relay(self, conn_id: int, stream_id: int, origin: "Response") -> None:
        """delivers a deferred response by relaying an origin verbatim NW060900.

        the deferred counterpart of Responder.relay: emits origin's status,
        headers, and body without re-signing, so a proxy answering a deferred
        request from its loop preserves the origin's end-to-end signature.

        raises AppError (app-not-found) when the request is no longer parked.
        """
        check(
            lib.nwep_server_relay(
                self._handle, conn_id, stream_id, origin._raw_message()
            )
        )

    def respond_blit(self, conn_id: int, stream_id: int, frame: bytes) -> None:
        """delivers a deferred response by blitting a captured frame NW000017.

        writes the frame verbatim onto the parked stream, no re-encode or re-sign.
        the frame must match the connection's codec and still be within its
        signature-ts + max-age. capture frames with Responder.capture.

        raises AppError (app-not-found) when the request is no longer parked.
        """
        check(
            lib.nwep_server_respond_blit(
                self._handle, conn_id, stream_id, frame, len(frame)
            )
        )

    def stream_send(self, conn_id: int, stream_id: int, body: bytes) -> int:
        """queues body bytes on a streamed response, returning how many were taken NW060200.

        for a stream begun with Responder.stream. the accepted count may be fewer
        than len(body) (including 0) under back-pressure; let tick drain, then
        retry the unaccepted tail.

        returns the number of bytes accepted (0 to len(body)).
        raises an error from the transport on failure.
        """
        return check(
            lib.nwep_server_stream_send(
                self._handle, conn_id, stream_id, _body_ptr(body), len(body)
            )
        )

    def stream_end(self, conn_id: int, stream_id: int) -> None:
        """ends a streamed response, flushing the trailer and writing FIN NW060200.

        no further stream_send is permitted on this stream after it. the trailer
        carries the response signature the client verifies with Stream.verify.

        raises an error from the transport on failure.
        """
        check(lib.nwep_server_stream_end(self._handle, conn_id, stream_id))

    def notify(
        self,
        conn_id: int,
        event: str,
        body: bytes = b"",
        headers: Optional["_message.HeadersArg"] = None,
    ) -> None:
        """pushes a NOTIFY to a connection on a fresh stream NW060200.

        a server-initiated push carrying an :event and an optional body; the
        client drains it with Client.poll_notify. the push is flushed on the next
        tick. the conn_id comes from a request the connection sent (Request.conn_id).

        raises IdentityError (identity-not-found) for an unknown conn_id.
        """
        header_array, _keep = _message.encode_headers(headers)
        check(
            lib.nwep_server_notify(
                self._handle,
                conn_id,
                event.encode("utf-8"),
                header_array,
                _body_ptr(body),
                len(body),
            )
        )

    def metrics(self) -> ServerMetrics:
        """returns a snapshot of this reactor's counters and gauges NW000017.

        call from the tick thread. returns the ServerMetrics.
        raises InternalError on a null handle.
        """
        out = ffi.new("nwep_server_metrics *")
        check(lib.nwep_server_metrics_get(self._handle, out))
        return ServerMetrics(
            connections_active=int(out.connections_active),
            connections_accepted=int(out.connections_accepted),
            connections_refused=int(out.connections_refused),
            connections_closed=int(out.connections_closed),
            bytes_received=int(out.bytes_received),
            bytes_sent=int(out.bytes_sent),
            datagrams_received=int(out.datagrams_received),
            datagrams_sent=int(out.datagrams_sent),
            requests_dispatched=int(out.requests_dispatched),
            requests_shed=int(out.requests_shed),
            parked_active=int(out.parked_active),
            load=int(out.load),
        )

    @property
    def load(self) -> int:
        """returns the server's load gauge, 0 to 100 NW000017."""
        return lib.nwep_server_load(self._handle)

    def set_overloaded(self, on: bool) -> None:
        """forces the load gauge to 100 (or clears it), shedding new work NW000017.

        lets an embedder signal back-pressure from a resource the library cannot
        see (a full disk, a saturated backend), since nwep has no global allocator
        to watermark.
        """
        lib.nwep_server_set_overloaded(self._handle, 1 if on else 0)

    def conn_compression(self, conn_id: int) -> Compression:
        """returns the codec a connection negotiated NW000017.

        also reachable as Request.compression. UNKNOWN for an unknown connection.
        """
        return _to_compression(lib.nwep_server_conn_compression(self._handle, conn_id))

    def last_handshake_error(self) -> Optional["Error"]:
        """returns why the most recent inbound handshake was rejected, or None.

        a rejected handshake is closed silently to the peer NW150200, so this is
        the operator's only window into why inbound dials fail (for example a
        crypto-fatal-nodeid-mismatch). a local diagnostic, never transmitted.

        returns the rejection as an Error instance (its code and name), or None
        when no fatal handshake failure has occurred.
        """
        code = lib.nwep_server_last_handshake_error(self._handle)
        if code == 0:
            return None
        from .errors import from_code

        return from_code(code)

    def drain(self) -> None:
        """begins a graceful drain: stop accepting, finish in-flight work NW000017.

        keep ticking until is_drained is true, then close. lets a reactor hand off
        to a replacement with no dropped connections.
        """
        check(lib.nwep_server_drain(self._handle))

    @property
    def is_drained(self) -> bool:
        """returns whether a drain has completed and no connections remain NW000017."""
        return lib.nwep_server_is_drained(self._handle) == 1

    @property
    def raw(self) -> "_sys.CData":
        """returns the raw c nwep_server pointer, the escape hatch to sys NWG0200."""
        return self._handle

    def close(self) -> None:
        """shuts the server down and closes its socket. idempotent."""
        if not self._closed:
            lib.nwep_server_close(self._handle)
            self._closed = True
            self._handler_cb = None

    def _install_handler(self, handler: Handler) -> None:
        """wires a python handler in behind an exception-safe c trampoline NWG0900.

        the trampoline never lets a python exception unwind into c: it prints the
        traceback and returns a generic error, which the library turns into an
        error response. keeps the cffi callback alive for the server's lifetime.
        """
        server_ptr = self._handle

        @ffi.callback("nwep_handler_fn")
        def trampoline(c_server, conn_id, stream_id, c_request, resp_buf, _userdata):
            try:
                request = Request(c_request, server_ptr, conn_id, stream_id)
                responder = Responder(resp_buf, server_ptr, conn_id, stream_id)
                reply = handler(request, responder)
                if not isinstance(reply, Reply):
                    sys.stderr.write(
                        "nwep: handler returned %r, expected a Reply from "
                        "responder.ok()/.status()/.not_found()/.error()/.defer()\n"
                        % (type(reply).__name__,)
                    )
                    return -801
                return _DEFER if reply.deferred else 0
            except Exception:  # no python exception may unwind into c NWG0900.
                traceback.print_exc()
                return -801

        self._handler_cb = trampoline
        check(lib.nwep_server_set_handler(self._handle, trampoline, ffi.NULL))

    def __enter__(self) -> "Server":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def __repr__(self) -> str:
        state = "closed" if self._closed else f"port={self.local_port}"
        return f"Server({state})"


class ServerBuilder:
    """ServerBuilder constructs a Server in prose NWG0300.

    set the identity and bind address, optionally a request handler, then build().
    build() is the driven terminal returning a Server you drive yourself; a managed
    serve() terminal that owns the loop is layered on later NWG0200.
    """

    __slots__ = (
        "_identity",
        "_bind",
        "_handler",
        "_max_parked",
        "_reuse_port",
        "_fd",
        "_shard_id",
        "_dht_contacts",
        "_dht_seq",
        "_announce",
    )

    def __init__(self):
        self._identity: Optional[Identity] = None
        self._bind: Optional[Address] = None
        self._handler: Optional[Handler] = None
        self._max_parked: Optional[int] = None
        self._reuse_port: bool = False
        self._fd: Optional[int] = None
        self._shard_id: Optional[int] = None
        # the managed-dht options, used only by serve (the managed terminal). when
        # _dht_contacts is not None serve attaches a dht on the owner thread.
        self._dht_contacts = None
        self._dht_seq: int = 0
        self._announce: Optional[Address] = None

    def identity(self, identity: Identity) -> "ServerBuilder":
        """sets the identity the server proves ownership of in the handshake NW090000."""
        self._identity = identity
        return self

    def bind(self, address: Address) -> "ServerBuilder":
        """sets the udp address to bind, the kernel picks the port for port 0 NW110300."""
        self._bind = address
        return self

    def on_request(self, handler: Handler) -> "ServerBuilder":
        """sets the request handler, a callable (Request, Responder) -> Reply NW060000."""
        self._handler = handler
        return self

    def max_parked(self, limit: int) -> "ServerBuilder":
        """caps how many deferred responses may be outstanding at once NW000017.

        bounds memory from defer()'d requests; beyond the cap, new deferrable
        requests are shed. applied when the server is built.
        """
        self._max_parked = limit
        return self

    def reuse_port(self) -> "ServerBuilder":
        """binds with SO_REUSEPORT so N reactors can share one port NW000017.

        the kernel fans connections across the pool. linux/android only; query
        reuse_port_supported() first. used with bind(); ignored when from_fd is set.
        """
        self._reuse_port = True
        return self

    def dht(self, contacts) -> "ServerBuilder":
        """attaches a managed dht seeded with contacts, a serve-only option NW110000.

        when set, serve() attaches a dht on the owner thread, joins the network, and
        ticks it alongside the server, so RunningServer.resolve resolves a node_id to
        an address without the caller running any loop. ignored by build (the driven
        terminal); attach a Dht yourself there with Dht.attach. contacts is an
        iterable of Bootstrap.
        """
        self._dht_contacts = list(contacts)
        return self

    def dht_initial_seq(self, seq: int) -> "ServerBuilder":
        """sets the managed dht's initial announcement sequence NW110600."""
        self._dht_seq = seq
        return self

    def announce_as(self, address: Address) -> "ServerBuilder":
        """makes the managed dht re-announce this service address periodically NW110300."""
        self._announce = address
        return self

    def from_fd(self, fd: int, shard_id: Optional[int] = None) -> "ServerBuilder":
        """adopts a caller-created, already-bound udp socket NW000017.

        the portable multi-reactor primitive: each reactor process makes its own
        AF_INET6 SO_REUSEPORT socket and hands the fd here (ownership transfers to
        the server). bind() is not needed. pass shard_id NW000017 to stamp
        every issued connection id with the shard so a steering program routes
        packets to the owning reactor.
        """
        self._fd = fd
        self._shard_id = shard_id
        return self

    def build(self) -> Server:
        """binds the socket and returns a driven Server, not yet looping NWG0200.

        the driven terminal: you own the loop. the socket comes from bind() (plain
        or reuse_port()) or from_fd(). returns the Server, bound and ready for the
        first tick.
        raises ConfigError when the identity or bind/fd source is unset, and a bind
        or network error from the transport.
        """
        if self._identity is None:
            raise _missing("identity")
        out = ffi.new("nwep_server **")
        kp = self._identity._keypair()
        if self._fd is not None:
            if self._shard_id is not None:
                check(
                    lib.nwep_server_listen_fd_sharded(out, kp, self._fd, self._shard_id)
                )
            else:
                check(lib.nwep_server_listen_fd(out, kp, self._fd))
        else:
            if self._bind is None:
                raise _missing("bind address")
            if self._reuse_port:
                check(lib.nwep_server_listen_reuseport(out, kp, self._bind._raw()))
            else:
                check(lib.nwep_server_listen(out, kp, self._bind._raw()))
        server = Server(out[0])
        if self._max_parked is not None:
            lib.nwep_server_set_max_parked(server._handle, self._max_parked)
        if self._handler is not None:
            server._install_handler(self._handler)
        return server

    async def serve(self) -> "RunningServer":
        """builds the server and runs its loop on a runtime thread NWG0200 NWG0600.

        the managed terminal: the runtime owns the loop. the server is built and
        driven on a dedicated owner thread, and the handler fires there. mirrors
        build() but you never call tick yourself.

        returns the RunningServer once it is bound and listening.
        raises ConfigError when the identity or bind address is unset, and a bind
        or network error from the transport.
        """
        from . import runtime

        return await runtime._serve(self)


def _body_ptr(body: bytes) -> "_sys.CData":
    """returns the c body pointer, NULL for an empty body (the header's contract)."""
    return body if body else ffi.NULL


def _missing(what: str):
    from .errors import ConfigMissing  # type: ignore[attr-defined]

    return ConfigMissing(f"server builder is missing the {what}")


def reuse_port_supported() -> bool:
    """returns whether SO_REUSEPORT multi-reactor pools are available NW000017.

    True on linux/android, False elsewhere. query it before building a pool that
    shares one port; where it is unsupported the kernel-fanned model is
    unavailable and a single acceptor is the supported scale model.
    """
    return lib.nwep_reuse_port_supported() == 1


def cid_shard_id(cid: bytes) -> Optional[int]:
    """returns the shard id a server stamped into a connection id, or None NW000017.

    decodes the on-wire cid sharding scheme a steering program reads (byte 0 is the
    marker, bytes 1..3 a big-endian shard id). lets a userspace fallback or a test
    recover the shard.

    returns the shard id, or None when cid is not shard-encoded.
    """
    rc = lib.nwep_cid_shard_id(cid, len(cid))
    return None if rc < 0 else rc
