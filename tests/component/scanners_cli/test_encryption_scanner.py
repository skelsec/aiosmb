"""SMB encryption enforcement scanner behavior against deterministic fakes."""

import asyncio
import sys

import pytest
from asysocks.unicomm.common.scanner.common import (
    ScannerData,
    ScannerError,
    ScannerResultType,
)

if sys.version_info < (3, 9):
    pytest.skip("blocked by KF-0107", allow_module_level=True)

from aiosmb.commons.exceptions import (
    SMBException,
    SMBUnsupportedDialectSelected,
)
from aiosmb.examples.scanners.smbencryption import SMBEncryptionScanner
from aiosmb.protocol.common import NegotiateDialects
from aiosmb.wintypes.ntstatus import NTStatus


pytestmark = pytest.mark.component


class FakeFactory:
    def __init__(self, connections):
        self.connections = list(connections)
        self.calls = []

    def create_connection_newtarget(
        self, target, advertise_encryption=True
    ):
        self.calls.append((target, advertise_encryption))
        return self.connections.pop(0)


class FakeConnection:
    def __init__(
        self,
        login_error=None,
        echo_error=None,
        dialect=NegotiateDialects.SMB311,
        supports_encryption=True,
        session_encryption_required=False,
    ):
        self.login_error = login_error
        self.echo_error = echo_error
        self.selected_dialect = dialect
        self.SupportsEncryption = supports_encryption
        self.session_encryption_required = session_encryption_required
        self.supported_dialects = None
        self.login_calls = 0
        self.echo_calls = 0
        self.entered = False
        self.exited = False

    async def __aenter__(self):
        self.entered = True
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        self.exited = True

    async def login(self):
        self.login_calls += 1
        return self.login_error is None, self.login_error

    async def echo(self):
        self.echo_calls += 1
        return self.echo_error is None, self.echo_error


async def run_scanner(connections):
    factory = FakeFactory(connections)
    output = asyncio.Queue()
    await SMBEncryptionScanner(factory).run(
        "target-id",
        "files.example",
        output,
    )
    return factory, output.get_nowait()


@pytest.mark.asyncio
async def test_encryption_scanner_reports_clear_session_accepted() -> None:
    baseline = FakeConnection(
        supports_encryption=True,
        session_encryption_required=False,
    )
    probe = FakeConnection(supports_encryption=False)

    factory, row = await run_scanner([baseline, probe])

    assert factory.calls == [
        ("files.example", True),
        ("files.example", False),
    ]
    assert baseline.entered is True
    assert baseline.exited is True
    assert probe.entered is True
    assert probe.exited is True
    assert baseline.login_calls == baseline.echo_calls == 1
    assert probe.login_calls == probe.echo_calls == 1
    assert isinstance(row, ScannerData)
    assert row.type is ScannerResultType.DATA
    assert row.data.to_dict() == {
        "DIALECT": "SMB311",
        "ENCRYPTION_SUPPORTED": True,
        "SESSION_ENCRYPTION_REQUIRED": False,
        "ENCRYPTION_ENFORCED": False,
        "PROBE_STATUS": "CLEAR_SESSION_ACCEPTED",
    }


@pytest.mark.asyncio
async def test_encryption_scanner_reports_clear_session_rejected() -> None:
    baseline = FakeConnection(session_encryption_required=True)
    rejection = SMBException(
        "unencrypted session rejected",
        NTStatus.ACCESS_DENIED,
    )
    probe = FakeConnection(login_error=rejection, supports_encryption=False)

    _, row = await run_scanner([baseline, probe])

    assert isinstance(row, ScannerData)
    assert row.data.to_dict() == {
        "DIALECT": "SMB311",
        "ENCRYPTION_SUPPORTED": True,
        "SESSION_ENCRYPTION_REQUIRED": True,
        "ENCRYPTION_ENFORCED": True,
        "PROBE_STATUS": "CLEAR_SESSION_REJECTED",
    }
    assert probe.echo_calls == 0


@pytest.mark.asyncio
async def test_encryption_scanner_reports_clear_echo_rejected() -> None:
    baseline = FakeConnection(session_encryption_required=True)
    rejection = SMBException(
        "unencrypted echo rejected",
        NTStatus.NETWORK_ACCESS_DENIED,
    )
    probe = FakeConnection(
        echo_error=rejection,
        supports_encryption=False,
    )

    _, row = await run_scanner([baseline, probe])

    assert isinstance(row, ScannerData)
    assert row.data.to_dict()["ENCRYPTION_ENFORCED"] is True
    assert row.data.to_dict()["PROBE_STATUS"] == "CLEAR_ECHO_REJECTED"


@pytest.mark.asyncio
async def test_encryption_scanner_reports_smb3_unsupported_as_data() -> None:
    baseline = FakeConnection(
        login_error=SMBUnsupportedDialectSelected(),
        dialect=None,
        supports_encryption=False,
    )

    factory, row = await run_scanner([baseline])

    assert factory.calls == [("files.example", True)]
    assert isinstance(row, ScannerData)
    assert row.data.to_dict() == {
        "DIALECT": None,
        "ENCRYPTION_SUPPORTED": False,
        "SESSION_ENCRYPTION_REQUIRED": False,
        "ENCRYPTION_ENFORCED": None,
        "PROBE_STATUS": "SMB3_UNSUPPORTED",
    }


@pytest.mark.asyncio
async def test_encryption_scanner_surfaces_baseline_authentication_failure() -> None:
    baseline = FakeConnection(
        login_error=RuntimeError("authentication rejected"),
    )

    _, row = await run_scanner([baseline])

    assert isinstance(row, ScannerError)
    assert row.type is ScannerResultType.ERROR
    assert "authentication rejected" in row.data
    assert "Traceback:" in row.data


@pytest.mark.asyncio
async def test_encryption_scanner_keeps_unexpected_probe_failure_inconclusive() -> None:
    baseline = FakeConnection()
    probe = FakeConnection(
        login_error=RuntimeError("connection reset"),
        supports_encryption=False,
    )

    _, row = await run_scanner([baseline, probe])

    assert isinstance(row, ScannerError)
    assert "connection reset" in row.data
    assert "ENCRYPTION_ENFORCED" not in row.data
