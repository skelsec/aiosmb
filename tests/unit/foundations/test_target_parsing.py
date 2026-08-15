"""Deterministic URL, target, and DCE/RPC binding parsing tests."""

import pytest

from asysocks.unicomm.common.target import UniProto

from aiosmb.commons.connection.target import SMBTarget
from aiosmb.dcerpc.v5.common.connection.connectionstring import (
    DCERPCStringBinding,
    DCERPCStringBindingCompose,
)
from aiosmb.dcerpc.v5.common.connection.target import (
    DCERPCTarget,
    DCERPCTCPTarget,
)
from aiosmb.protocol.common import NegotiateDialects
from aiosmb.protocol.smb2.commands.negotiate import SMB2CompressionType


pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "url,expected",
    [
        (
            "smb://192.0.2.10",
            {
                "ip": "192.0.2.10",
                "hostname": None,
                "port": 445,
                "protocol": UniProto.CLIENT_TCP,
                "path": None,
                "timeout": 5,
                "fragment": None,
                "compression": None,
            },
        ),
        (
            "smb3://files.example:1445/share/report.txt"
            "?timeout=9&fragment=5&compress=1",
            {
                "ip": None,
                "hostname": "files.example",
                "port": 1445,
                "protocol": UniProto.CLIENT_TCP,
                "path": "/share/report.txt",
                "timeout": 9,
                "fragment": 5,
                "compression": 1,
            },
        ),
        (
            "smb-quic://files.example/share",
            {
                "ip": None,
                "hostname": "files.example",
                "port": 443,
                "protocol": UniProto.CLIENT_QUIC,
                "path": "/share",
                "timeout": 5,
                "fragment": None,
                "compression": None,
            },
        ),
        (
            "smb2-udp://192.0.2.20:138",
            {
                "ip": "192.0.2.20",
                "hostname": None,
                "port": 138,
                "protocol": UniProto.CLIENT_UDP,
                "path": None,
                "timeout": 5,
                "fragment": None,
                "compression": None,
            },
        ),
    ],
)
def test_smb_url_parses_transport_endpoint_and_options(url: str, expected: dict) -> None:
    target = SMBTarget.from_url(url)

    actual = {name: getattr(target, name) for name in expected}
    assert actual == expected


def test_smb_url_dialect_selects_wire_revisions() -> None:
    target = SMBTarget.from_url("smb3://files.example")

    assert set(target.preferred_dialects) == {
        NegotiateDialects.SMB300,
        NegotiateDialects.SMB302,
        NegotiateDialects.SMB311,
    }


def test_smb_url_parses_compression_threshold() -> None:
    target = SMBTarget.from_url(
        "smb311://files.example?compress=1&compress_min=8192"
    )

    assert target.compression == 1
    assert target.compression_min_size == 8192


def test_smb_url_parses_ordered_compression_algorithms() -> None:
    target = SMBTarget.from_url(
        "smb311://files.example?compress_algorithms=lz4,lz77_huffman,lznt1"
    )

    assert not target.compression
    assert target.compression_algorithms == (
        SMB2CompressionType.LZ4,
        SMB2CompressionType.LZ77_Huffman,
        SMB2CompressionType.LZNT1,
    )
    copied = target.get_copy("192.0.2.44", 445)
    assert copied.compression_algorithms == target.compression_algorithms


@pytest.mark.parametrize(
    "url,error_match",
    [
        ("ftp://files.example", "FTP"),
        ("smb-udp://files.example", "Port must be provided"),
        ("smb://files.example?fragment=large", None),
        ("smb://files.example?compress_min=0", "positive"),
        (
            "smb311://files.example?compress_algorithms=pattern_v1",
            "Unsupported unchained",
        ),
        (
            "smb311://files.example?compress_algorithms=lz77,lz77",
            "unique",
        ),
        ("smb://files.example:70000", "Port out of range"),
    ],
)
def test_smb_url_rejects_malformed_configuration(
    url: str, error_match: str
) -> None:
    with pytest.raises(Exception, match=error_match):
        SMBTarget.from_url(url)


@pytest.mark.xfail(
    strict=True,
    reason="KF-0101: legacy target parser constructs an endpoint-less target",
)
def test_legacy_target_string_parses_domain_address_and_dc() -> None:
    target = SMBTarget.from_connection_string(
        "EXAMPLE/user@192.0.2.10/192.0.2.53"
    )

    assert target.domain == "EXAMPLE"
    assert target.ip == "192.0.2.10"
    assert target.hostname is None
    assert target.port == 445
    assert target.dc_ip == "192.0.2.53"


def test_dcerpc_binding_golden_parse_and_compose() -> None:
    binding_text = (
        "12345678-1234-5678-9abc-def012345678@"
        "ncacn_ip_tcp:server.example[endpoint=135,security=packet]"
    )

    binding = DCERPCStringBinding(binding_text)

    assert binding.get_uuid() == "12345678-1234-5678-9abc-def012345678"
    assert binding.get_protocol_sequence() == "ncacn_ip_tcp"
    assert binding.get_network_address() == "server.example"
    assert binding.get_endpoint() == "135"
    assert binding.get_options() == ["security=packet"]
    assert str(binding) == (
        "12345678-1234-5678-9abc-def012345678@"
        "ncacn_ip_tcp:server.example[135,security=packet]"
    )
    assert (
        DCERPCStringBindingCompose(
            binding.get_uuid(),
            binding.get_protocol_sequence(),
            binding.get_network_address(),
            binding.get_endpoint(),
            binding.get_options(),
        )
        == str(binding)
    )


def test_dcerpc_tcp_target_parses_numeric_endpoint() -> None:
    target = DCERPCTarget.from_connection_string(
        "ncacn_ip_tcp:192.0.2.30[49152]",
        timeout=7,
        domain="EXAMPLE",
    )

    assert isinstance(target, DCERPCTCPTarget)
    assert target.ip == "192.0.2.30"
    assert target.port == 49152
    assert target.timeout == 7
    assert target.domain == "EXAMPLE"
    assert target.protocol is UniProto.CLIENT_TCP
    assert target.rpcprotocol == "ncacn_ip_tcp"


@pytest.mark.parametrize(
    "binding",
    [
        "not a binding",
        "unknown_protocol:server.example[135]",
        "ncacn_ip_tcp:server.example[not-a-port]",
    ],
)
def test_dcerpc_target_rejects_malformed_bindings(binding: str) -> None:
    with pytest.raises(Exception):
        DCERPCTarget.from_connection_string(binding)
