"""Scanner executor behavior against deterministic fake connections."""

import asyncio
import enum
import sys

import pytest
from asysocks.unicomm.common.scanner.common import (
    ScannerData,
    ScannerError,
    ScannerResultType,
)

if sys.version_info < (3, 9):
    pytest.skip("blocked by KF-0107", allow_module_level=True)

from aiosmb.examples.scanners.smbfinger import SMBFingerScanner
from aiosmb.examples.scanners.smbproto import SMBProtocolScanner


pytestmark = pytest.mark.component


class Protocol(enum.Enum):
    SMB1 = 1
    SMB311 = 2


class FakeFactory:
    def __init__(self, connections):
        self.connections = list(connections)
        self.targets = []

    def create_connection_newtarget(self, target):
        self.targets.append(target)
        return self.connections.pop(0)


class FakeProtocolConnection:
    def __init__(self, response):
        self.response = response
        self.calls = []

    async def protocol_test(self, protocols):
        self.calls.append(protocols)
        return self.response


class FakeFingerConnection:
    def __init__(self, result=None, error=None):
        self.result = result
        self.error = error
        self.calls = 0

    async def fake_login(self):
        self.calls += 1
        return self.result, self.error


class FakeServerInfo:
    def to_json(self):
        return '{"dns_computer_name": "files.example"}'

    def to_tsv(self, separator):
        return "files.example{}Windows".format(separator)

    def to_dict(self):
        return {
            "dns_computer_name": "files.example",
            "product_name": "Windows",
        }


@pytest.mark.asyncio
async def test_protocol_scanner_uses_fresh_connections_and_emits_supported_rows() -> None:
    smb1 = FakeProtocolConnection((True, True, False, object(), None))
    smb311 = FakeProtocolConnection((False, True, True, object(), None))
    factory = FakeFactory([smb1, smb311])
    scanner = SMBProtocolScanner(factory, [Protocol.SMB1, Protocol.SMB311])
    output = asyncio.Queue()

    await scanner.run("target-id", "files.example", output)

    assert factory.targets == ["files.example", "files.example"]
    assert smb1.calls == [[Protocol.SMB1]]
    assert smb311.calls == [[Protocol.SMB311]]
    assert output.qsize() == 1
    row = output.get_nowait()
    assert isinstance(row, ScannerData)
    assert row.type is ScannerResultType.DATA
    assert row.resid == "files.example"
    assert row.data.to_dict() == {
        "PROTO": "SMB1",
        "SIGN_ENABLED": True,
        "SIGN_ENFORCED": False,
    }


def test_protocol_scanner_accepts_protocol_mapping_and_single_value() -> None:
    factory = FakeFactory([])

    mapped = SMBProtocolScanner(factory, {Protocol.SMB1: "legacy"})
    single = SMBProtocolScanner(factory, Protocol.SMB311)

    assert mapped.protocols == [Protocol.SMB1]
    assert single.protocols == [Protocol.SMB311]


@pytest.mark.asyncio
async def test_protocol_scanner_converts_connection_failure_to_scanner_error() -> None:
    failure = RuntimeError("negotiate failed")
    connection = FakeProtocolConnection((False, False, False, None, failure))
    output = asyncio.Queue()

    await SMBProtocolScanner(FakeFactory([connection]), Protocol.SMB311).run(
        "target-id", "files.example", output
    )

    row = output.get_nowait()
    assert isinstance(row, ScannerError)
    assert row.type is ScannerResultType.ERROR
    assert row.resid == "files.example"
    assert "negotiate failed" in row.data
    assert "Traceback:" in row.data


@pytest.mark.asyncio
async def test_fingerprint_scanner_uses_fake_login_and_wraps_server_info() -> None:
    server_info = FakeServerInfo()
    connection = FakeFingerConnection(server_info)
    factory = FakeFactory([connection])
    output = asyncio.Queue()

    await SMBFingerScanner(factory).run("target-id", "files.example", output)

    assert connection.calls == 1
    assert factory.targets == ["files.example"]
    row = output.get_nowait()
    assert isinstance(row, ScannerData)
    assert row.resid == "files.example"
    assert row.data.to_dict() == {
        "dns_computer_name": "files.example",
        "product_name": "Windows",
    }
    assert row.data.to_line("|") == "files.example|Windows"


@pytest.mark.asyncio
async def test_fingerprint_scanner_converts_fake_login_error_to_scanner_error() -> None:
    connection = FakeFingerConnection(error=RuntimeError("authentication rejected"))
    output = asyncio.Queue()

    await SMBFingerScanner(FakeFactory([connection])).run(
        "target-id", "files.example", output
    )

    row = output.get_nowait()
    assert isinstance(row, ScannerError)
    assert row.resid == "files.example"
    assert "authentication rejected" in row.data
    assert "Traceback:" in row.data
