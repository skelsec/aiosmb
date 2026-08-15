"""Deterministic contracts for DCERPC bindings, targets, and UUID helpers."""

import struct

import pytest

from asysocks.unicomm.common.proxy import UniProxyTarget
from asysocks.unicomm.common.target import UniProto

from aiosmb.dcerpc.v5 import uuid as rpc_uuid
from aiosmb.dcerpc.v5.common.connection.connectionstring import (
    DCERPCStringBinding,
    DCERPCStringBindingCompose,
)
from aiosmb.dcerpc.v5.common.connection.target import (
    DCERPCSMBTarget,
    DCERPCTCPTarget,
    DCERPCTarget,
)


pytestmark = pytest.mark.unit

UUID_TEXT = "00112233-4455-6677-8899-AABBCCDDEEFF"
UUID_WIRE = bytes.fromhex("33221100554477668899aabbccddeeff")


class _SMBTarget:
    proxies = None
    domain = "EXAMPLE"
    dc_ip = "192.0.2.53"
    timeout = 7

    def get_ip_or_hostname(self):
        return "192.0.2.20"

    def get_hostname_or_ip(self):
        return "server.example.test"

    def to_target_string(self):
        return "cifs/server.example.test@EXAMPLE"


class _SMBConnection:
    target = _SMBTarget()


def test_string_binding_parses_uuid_endpoint_and_options():
    binding = DCERPCStringBinding(
        UUID_TEXT
        + "@ncacn_ip_tcp:server.example.test[endpoint=49152,security=privacy]"
    )

    assert binding.get_uuid() == UUID_TEXT
    assert binding.get_protocol_sequence() == "ncacn_ip_tcp"
    assert binding.get_network_address() == "server.example.test"
    assert binding.get_endpoint() == "49152"
    assert binding.get_options() == ["security=privacy"]
    assert str(binding) == (
        UUID_TEXT
        + "@ncacn_ip_tcp:server.example.test[49152,security=privacy]"
    )


@pytest.mark.parametrize(
    "components, expected",
    [
        ((None, "ncacn_ip_tcp", "192.0.2.10", "135", []),
         "ncacn_ip_tcp:192.0.2.10[135]"),
        ((None, "ncacn_np", "host", "", []), "ncacn_np:host"),
        ((None, "ncacn_ip_tcp", "host", "", ["a=1", "b=2"]),
         "ncacn_ip_tcp:host[,a=1,b=2]"),
        ((UUID_TEXT, "ncalocal", "", "", []), UUID_TEXT + "@ncalocal:"),
    ],
)
def test_string_binding_compose_contract(components, expected):
    assert DCERPCStringBindingCompose(*components) == expected
    assert str(DCERPCStringBinding(expected)) == expected


def test_tcp_target_from_numeric_address():
    target = DCERPCTarget.from_connection_string(
        "ncacn_ip_tcp:192.0.2.10[135]", timeout=9
    )

    assert isinstance(target, DCERPCTCPTarget)
    assert target.ip == "192.0.2.10"
    assert target.hostname is None
    assert target.port == 135
    assert target.protocol is UniProto.CLIENT_TCP
    assert target.rpcprotocol == "ncacn_ip_tcp"
    assert target.timeout == 9
    assert target.get_ip_or_hostname() == "192.0.2.10"
    assert target.get_hostname_or_ip() == "192.0.2.10"


def test_tcp_target_preserves_hostname_domain_and_proxy_copy():
    proxy = UniProxyTarget()
    proxy.endpoint_ip = "192.0.2.30"
    proxy.endpoint_port = 4444
    proxies = [proxy]

    target = DCERPCTarget.from_connection_string(
        "ncacn_ip_tcp:server.example.test[49152]",
        timeout=4,
        proxies=proxies,
        domain="EXAMPLE",
    )

    assert target.ip is None
    assert target.hostname == "server.example.test"
    assert target.port == 49152
    assert target.domain == "EXAMPLE"
    assert target.to_target_string() == "cifs/server.example.test@EXAMPLE"
    assert target.proxies is not proxies
    assert target.proxies[0] is not proxy
    assert target.proxies[0].endpoint_ip == "192.0.2.30"


def test_named_pipe_target_uses_existing_smb_target_metadata():
    smb_connection = _SMBConnection()
    target = DCERPCTarget.from_connection_string(
        r"ncacn_np:ignored.example.test[\pipe\samr]",
        smb_connection=smb_connection,
        timeout=3,
    )

    assert isinstance(target, DCERPCSMBTarget)
    assert target.smb_connection is smb_connection
    assert target.ip == "192.0.2.20"
    assert target.hostname == "server.example.test"
    assert target.domain == "EXAMPLE"
    assert target.dc_ip == "192.0.2.53"
    assert target.pipe == r"\samr"
    assert target.port is None
    assert target.to_target_string() == "cifs/server.example.test@EXAMPLE"


@pytest.mark.xfail(
    strict=True,
    reason=(
        "KF-0401: ncacn_np target construction dereferences a missing "
        "SMB connection"
    ),
)
def test_named_pipe_target_can_be_created_without_existing_smb_connection():
    target = DCERPCTarget.from_connection_string(
        r"ncacn_np:server.example.test[\pipe\samr]"
    )

    assert isinstance(target, DCERPCSMBTarget)
    assert target.hostname == "server.example.test"
    assert target.pipe == r"\samr"


@pytest.mark.parametrize(
    "binding, message",
    [
        ("ncadg_ip_udp:192.0.2.1[135]", "UDP not implemented"),
        ("ncacn_http:server.example.test[593]", "HTTP not implemented"),
        ("ncalocal:[endpoint]", "LOCAL not implemented"),
        ("unknown:server[1]", "Unknown DCERPC protocol unknown"),
    ],
)
def test_target_rejects_unsupported_protocols(binding, message):
    with pytest.raises(Exception, match=message):
        DCERPCTarget.from_connection_string(binding)


def test_target_rejects_unknown_binding_object_type():
    with pytest.raises(Exception, match="Unknown string binding type"):
        DCERPCTarget.from_connection_string(object())


def test_target_equality_and_hash_cover_connection_properties():
    first = DCERPCTarget.from_connection_string(
        "ncacn_ip_tcp:192.0.2.10[135]", timeout=2
    )
    same = DCERPCTarget.from_connection_string(
        "ncacn_ip_tcp:192.0.2.10[135]", timeout=2
    )
    different = DCERPCTarget.from_connection_string(
        "ncacn_ip_tcp:192.0.2.10[445]", timeout=2
    )

    assert first == same
    assert hash(first) == hash(same)
    assert first != different
    assert first != object()


def test_uuid_binary_and_text_round_trip_uses_rpc_mixed_endianness():
    assert rpc_uuid.string_to_bin(UUID_TEXT) == UUID_WIRE
    assert rpc_uuid.bin_to_string(UUID_WIRE) == UUID_TEXT


def test_uuid_tuple_and_version_wire_contract():
    wire = rpc_uuid.uuidtup_to_bin((UUID_TEXT, "3.7"))

    assert wire == UUID_WIRE + bytes.fromhex("03000700")
    assert rpc_uuid.bin_to_uuidtup(wire) == (UUID_TEXT, "3.7")
    assert rpc_uuid.stringver_to_bin("3.7") == bytes.fromhex("03000700")
    assert rpc_uuid.uuidtup_to_bin((UUID_TEXT,)) is None


@pytest.mark.parametrize(
    "text, expected_version",
    [
        (UUID_TEXT, "1.0"),
        ("interface " + UUID_TEXT + " version 12.34", "12.34"),
        ("{" + UUID_TEXT + "} v 2.5", "2.5"),
    ],
)
def test_uuid_tuple_text_extraction(text, expected_version):
    assert rpc_uuid.string_to_uuidtup(text) == (UUID_TEXT, expected_version)


def test_uuid_tuple_display_contract():
    assert rpc_uuid.uuidtup_to_string((UUID_TEXT, (3, 7))) == (
        UUID_TEXT + " v3.7"
    )


def test_uuid_generate_uses_four_packed_random_words(monkeypatch):
    values = iter([1, 2, 3, 4])
    monkeypatch.setattr(rpc_uuid, "randrange", lambda top: next(values))

    generated = rpc_uuid.generate()

    assert len(generated) == 16
    assert struct.unpack("IIII", generated) == (1, 2, 3, 4)
