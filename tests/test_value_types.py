"""value-type slice tests: Method NW050000, Status NW080000, Address NW110300, Uri NW040400."""

from __future__ import annotations

import pytest

import nwep
from nwep import Address, Identity, Method, Status, Uri


def test_method_is_its_wire_code_and_token() -> None:
    assert int(Method.READ) == 0
    assert int(Method.HEAD) == 7
    assert str(Method.READ) == "read"
    assert str(Method.DELETE) == "delete"
    assert Method(2) is Method.UPDATE


def test_status_is_its_wire_code_and_token() -> None:
    assert int(Status.OK) == 0
    assert str(Status.NOT_FOUND) == "not-found"
    assert str(Status.RATE_LIMITED) == "rate-limited"
    assert str(Status.RANGE_NOT_SATISFIABLE) == "range-not-satisfiable"
    assert Status(10) is Status.NOT_FOUND
    assert Status(5) is Status.MOVED
    assert Status(20) is Status.TIMEOUT
    assert Status(21) is Status.NOT_IMPLEMENTED


def test_address_constructors_and_port() -> None:
    assert Address.loopback(443).port == 443
    assert Address.wildcard(8080).port == 8080
    assert Address.ipv4_mapped(127, 0, 0, 1, 9000).port == 9000


def test_address_equality_and_bytes() -> None:
    a = Address.loopback(443)
    b = Address.loopback(443)
    c = Address.loopback(444)
    assert a == b
    assert hash(a) == hash(b)
    assert a != c
    assert len(bytes(a)) == 32


def test_address_from_bytes_round_trip() -> None:
    raw_v6 = bytes([0] * 15 + [1])  # ::1
    addr = Address.from_bytes(raw_v6, 1234)
    assert addr.port == 1234
    assert addr == Address.loopback(1234)


def test_address_from_bytes_rejects_wrong_length() -> None:
    with pytest.raises(ValueError):
        Address.from_bytes(b"short", 1)


def test_uri_parse_with_port() -> None:
    with Identity.generate() as identity:
        host = identity.node_id.base58()
        uri = Uri.parse(f"web://{host}:443/blob/42")
        assert uri.node_id == identity.node_id
        assert uri.port == 443
        assert uri.path == "/blob/42"
        assert str(uri) == f"web://{host}:443/blob/42"


def test_uri_parse_without_port_defaults_it() -> None:
    with Identity.generate() as identity:
        host = identity.node_id.base58()
        uri = Uri.parse(f"web://{host}/hello")
        # the parser fills in the default web/1 port when the uri omits one.
        assert uri.port == nwep.DEFAULT_PORT
        assert uri.path == "/hello"
        assert str(uri) == f"web://{host}:{nwep.DEFAULT_PORT}/hello"


def test_uri_parse_rejects_garbage() -> None:
    with pytest.raises(nwep.ProtocolError):
        Uri.parse("http://not-a-web-uri/")


def test_uri_equality_and_hash() -> None:
    with Identity.generate() as identity:
        host = identity.node_id.base58()
        u1 = Uri.parse(f"web://{host}:443/p")
        u2 = Uri.parse(f"web://{host}:443/p")
        assert u1 == u2
        assert hash(u1) == hash(u2)
