"""final-slice tests NW000017: multi-reactor + standalone verify + trust version.

reuse_port_supported, an adopted-socket reactor (from_fd), cid shard decoding,
the standalone response verify with an explicit origin key, and the trust build
version. core surfaces here; the trust version test is gated on the trust build.
"""

from __future__ import annotations

import socket
import threading
import time

import pytest

import nwep
from nwep import Address, Client, Identity, Method, Server, Status


def now_ms() -> int:
    return int(time.monotonic() * 1000)


def test_reuse_port_supported_is_a_bool() -> None:
    assert isinstance(nwep.reuse_port_supported(), bool)


def test_cid_shard_id_decodes_a_sharded_cid_and_rejects_others() -> None:
    # a non-shard-encoded cid (all zero) is not sharded.
    assert nwep.cid_shard_id(bytes(18)) is None
    # a cid with the shard marker + a big-endian shard id decodes to it.
    marker = 0x5E
    sharded = bytes([marker, 0x00, 0x07]) + bytes(15)  # shard 7.
    assert nwep.cid_shard_id(sharded) == 7


@pytest.mark.skipif(
    not nwep.reuse_port_supported(), reason="SO_REUSEPORT not supported here"
)
def test_from_fd_adopts_a_caller_socket() -> None:
    # a reactor that adopts a caller-made AF_INET6 udp socket (the multi-reactor
    # primitive). build the socket, hand its fd to the server, and serve over it.
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.bind(("::1", 0))
    port = sock.getsockname()[1]
    fd = sock.detach()  # ownership transfers to the server, which closes it.

    server_identity = Identity.generate()
    server = (
        Server.builder()
        .identity(server_identity)
        .on_request(lambda req, res: res.ok(b"adopted"))
        .from_fd(fd)
        .build()
    )
    stop = threading.Event()

    def loop():
        while not stop.is_set():
            server.tick(now_ms())
            time.sleep(0.002)

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()
    try:
        assert server.local_port == port
        with (
            Client.builder()
            .identity(Identity.generate())
            .connect(server.node_id, Address.loopback(port)) as client
        ):
            with client.send(Method.READ, "/x") as resp:
                assert resp.status == Status.OK
                assert resp.body == b"adopted"
    finally:
        stop.set()
        thread.join(timeout=2)
        server.close()
        server_identity.close()


def test_reuse_port_builder_option_when_supported() -> None:
    if not nwep.reuse_port_supported():
        # on unsupported platforms it returns config-invalid; assert that contract.
        with pytest.raises(nwep.ConfigError):
            Server.builder().identity(Identity.generate()).bind(
                Address.loopback(0)
            ).reuse_port().build()
        return
    identity = Identity.generate()
    server = (
        Server.builder()
        .identity(identity)
        .bind(Address.loopback(0))
        .reuse_port()
        .build()
    )
    try:
        assert server.local_port > 0
    finally:
        server.close()
        identity.close()


def test_standalone_verify_response_with_an_explicit_key() -> None:
    # serve a public signed response, then verify it OUT of band with the origin's
    # key (the cache/proxy path, no live connection to the origin needed).
    server_identity = Identity.generate()
    origin_pubkey = server_identity.public_key
    server = (
        Server.builder()
        .identity(server_identity)
        .bind(Address.loopback(0))
        .on_request(
            lambda req, res: res.header("cache-control", "public").ok(b"signed-body")
        )
        .build()
    )
    stop = threading.Event()

    def loop():
        while not stop.is_set():
            server.tick(now_ms())
            time.sleep(0.002)

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()
    try:
        with (
            Client.builder()
            .identity(Identity.generate())
            .connect(server.node_id, Address.loopback(server.local_port)) as client
        ):
            resp = client.send(Method.READ, "/doc")
        # verify with the explicit origin key (skip freshness with now_secs=0).
        nwep.verify_response(resp, origin_pubkey, "/doc", 0)
        # the wrong key fails.
        with pytest.raises(nwep.CryptoError):
            nwep.verify_response(resp, Identity.generate().public_key, "/doc", 0)
        # a wrong-length key is a value error.
        with pytest.raises(ValueError):
            nwep.verify_response(resp, b"short", "/doc", 0)
        resp.close()
    finally:
        stop.set()
        thread.join(timeout=2)
        server.close()
        server_identity.close()


def test_trust_version_when_available() -> None:
    import nwep.trust as trust

    if not trust.available():
        pytest.skip("trust layer absent (NWEP_LIB=core is set)")
    v = trust.version()
    assert isinstance(v, str) and len(v) > 0
