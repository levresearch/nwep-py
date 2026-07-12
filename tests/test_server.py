"""server slice tests NW070000: builder, lifecycle, the driven loop, responder.

the full request -> handler -> response round trip is exercised by the client
slice (a server needs a peer to dispatch), so these cover everything verifiable
without one: builder validation, the bound server's surface, that the driven loop
ticks cleanly with no traffic, and the responder's answer-exactly-once contract.
"""

from __future__ import annotations

import time

import pytest

import nwep
from nwep import Address, Identity, Reply, Responder, Server
from nwep import _sys


def now_ms() -> int:
    return int(time.monotonic() * 1000)


def _server(handler=None) -> Server:
    builder = Server.builder().identity(Identity.generate()).bind(Address.loopback(0))
    if handler is not None:
        builder = builder.on_request(handler)
    return builder.build()


def test_builder_requires_identity_and_bind() -> None:
    with pytest.raises(nwep.ConfigError):
        Server.builder().bind(Address.loopback(0)).build()
    with pytest.raises(nwep.ConfigError):
        Server.builder().identity(Identity.generate()).build()


def test_bound_server_exposes_its_node_id_port_and_fileno() -> None:
    identity = Identity.generate()
    expected = identity.node_id
    with (
        Server.builder().identity(identity).bind(Address.loopback(0)).build() as server
    ):
        assert server.node_id == expected
        assert server.local_port > 0  # kernel picked a real port for :0
        assert server.fileno() >= 0  # a real fd, registerable with a poller


def test_driven_loop_ticks_cleanly_with_no_traffic() -> None:
    with _server(lambda req, res: res.ok(b"hi")) as server:
        for _ in range(5):
            server.tick(now_ms())
            timeout = server.next_timeout(now_ms())
            assert timeout is None or timeout >= 0
            time.sleep(0.002)


def test_close_is_idempotent() -> None:
    server = _server()
    server.close()
    server.close()  # no double-free, no error.


def test_raw_handle_is_reachable_for_no_cliffs() -> None:
    with _server() as server:
        # the L1 server exposes its L0 pointer NWG0200, no cliffs.
        assert server.raw != _sys.ffi.NULL


def test_responder_answers_exactly_once() -> None:
    # defer() touches no buffer, so the exactly-once guard is testable standalone.
    responder = Responder(_sys.ffi.NULL, _sys.ffi.NULL, 1, 1)
    reply = responder.defer()
    assert isinstance(reply, Reply)
    assert reply.deferred is True
    with pytest.raises(RuntimeError):
        responder.defer()


def test_handler_signature_is_request_responder_to_reply() -> None:
    # a handler is just a callable returning a Reply; build accepts it without
    # firing it (dispatch needs a client, exercised in the client slice).
    seen = []

    def handler(req: nwep.Request, res: Responder) -> Reply:
        seen.append(req.path)
        return res.ok(b"hi")

    with _server(handler) as server:
        assert server.local_port > 0
    assert seen == []  # no peer connected, so the handler never fired.
