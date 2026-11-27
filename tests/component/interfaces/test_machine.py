"""SMBMachine context and delegation boundaries using local fakes only."""

import asyncio
import sys
from contextlib import asynccontextmanager
from types import SimpleNamespace
from typing import Any, List, Optional

import pytest

if sys.version_info < (3, 9):
    pytest.skip("blocked by KF-0107", allow_module_level=True)

from aiosmb.commons.interfaces import machine as machine_module
from aiosmb.commons.interfaces.machine import SMBMachine


pytestmark = [pytest.mark.component, pytest.mark.asyncio]
TIMEOUT = 0.5


class FakeRPCInstance:
    def __init__(self):
        self.close_count = 0

    async def close(self):
        self.close_count += 1


class FakeRPCService:
    calls = []  # type: List[Any]
    instance = None  # type: Optional[FakeRPCInstance]
    error = None  # type: Optional[Exception]

    @classmethod
    async def from_smbconnection(
        cls, connection, auth_level, open_value, perform_dummy
    ):
        cls.calls.append(
            (connection, auth_level, open_value, perform_dummy)
        )
        return cls.instance, cls.error


class FakeShareRPC:
    def __init__(self, rows):
        self.rows = rows

    async def list_shares(self):
        for row in self.rows:
            yield row


class FakeRPCContext:
    def __init__(self, rpc):
        self.rpc = rpc
        self.enter_count = 0
        self.exit_count = 0

    async def __aenter__(self):
        self.enter_count += 1
        return self.rpc

    async def __aexit__(self, exc_type, exc, traceback):
        self.exit_count += 1


class FakeDirectory:
    def __init__(self, list_error=None):
        self.list_error = list_error
        self.list_calls = []  # type: List[Any]
        self.create_calls = []  # type: List[Any]

    async def list(self, connection):
        self.list_calls.append(connection)
        if self.list_error is not None:
            return False, self.list_error
        return True, None

    def get_console_output(self):
        return ["dir\t0\t0\tchild", "file\t4\t0\treport.txt"]

    async def create_subdir(self, name, connection):
        self.create_calls.append((name, connection))
        return True, None


class FakeReadableFile:
    def __init__(self, chunks):
        self.chunks = chunks
        self.open_calls = []  # type: List[Any]
        self.close_count = 0

    async def open(self, connection, mode):
        self.open_calls.append((connection, mode))
        return True, None

    async def read_chunked(self):
        for chunk in self.chunks:
            yield chunk

    async def close(self):
        self.close_count += 1


class FakeDownloadFile:
    def __init__(self):
        self.open_calls = []  # type: List[Any]
        self.read_count = 0
        self.close_count = 0

    async def open(self, connection, mode):
        self.open_calls.append((connection, mode))
        return True, None

    async def read(self, count):
        self.read_count += 1
        if self.read_count == 1:
            return b"payload", None
        return b"", None

    async def close(self):
        self.close_count += 1


async def _collect(iterator):
    async def collect_all():
        return [item async for item in iterator]

    return await asyncio.wait_for(collect_all(), timeout=TIMEOUT)


async def test_machine_async_context_invokes_close():
    connection = object()
    machine = SMBMachine(connection)
    close_calls = []

    async def close():
        close_calls.append(True)

    machine.close = close

    async with machine as entered:
        assert entered is machine

    assert close_calls == [True]


async def test_connect_rpc_passes_options_and_closes_after_body_error():
    connection = object()
    instance = FakeRPCInstance()
    FakeRPCService.calls = []
    FakeRPCService.instance = instance
    FakeRPCService.error = None
    machine = SMBMachine(connection)

    with pytest.raises(RuntimeError, match="body failed"):
        async with machine.connect_rpc(
            FakeRPCService,
            auth_level="privacy",
            open=False,
            perform_dummy=True,
        ) as rpc:
            assert rpc is instance
            raise RuntimeError("body failed")

    assert FakeRPCService.calls == [
        (connection, "privacy", False, True)
    ]
    assert instance.close_count == 1


async def test_connect_rpc_propagates_factory_error_without_entering():
    expected_error = RuntimeError("rpc unavailable")
    FakeRPCService.calls = []
    FakeRPCService.instance = None
    FakeRPCService.error = expected_error
    machine = SMBMachine(object())

    with pytest.raises(RuntimeError, match="rpc unavailable"):
        async with machine.connect_rpc(FakeRPCService):
            raise AssertionError("context body must not run")


async def test_list_shares_builds_objects_and_propagates_rpc_error(
    monkeypatch,
):
    expected_error = RuntimeError("enumeration failed")
    rpc = FakeShareRPC(
        [
            ("data", 0, "team\x00", None),
            (None, None, None, expected_error),
        ]
    )
    context = FakeRPCContext(rpc)
    auth_calls = []

    def fake_context(connection, auth_level=None):
        auth_calls.append((connection, auth_level))
        return context

    monkeypatch.setattr(
        machine_module, "srvsrpc_from_smb", fake_context
    )
    connection = SimpleNamespace(
        target=SimpleNamespace(get_hostname_or_ip=lambda: "server.invalid")
    )
    machine = SMBMachine(connection, force_rpc_auth="integrity")

    rows = await _collect(machine.list_shares())

    assert len(rows) == 2
    share, error = rows[0]
    assert error is None
    assert share.name == "data"
    assert share.remark == "team"
    assert share.fullpath == r"\\server.invalid\data"
    assert rows[1] == (None, expected_error)
    assert auth_calls == [(connection, "integrity")]
    assert context.enter_count == 1
    assert context.exit_count == 1


async def test_list_directory_delegates_and_yields_console_rows():
    connection = object()
    directory = FakeDirectory()
    machine = SMBMachine(connection)

    rows = await _collect(machine.list_directory(directory))

    assert rows == [
        ("dir\t0\t0\tchild", None),
        ("file\t4\t0\treport.txt", None),
    ]
    assert directory.list_calls == [connection]


async def test_list_directory_yields_underlying_list_error_once():
    expected_error = RuntimeError("list failed")
    directory = FakeDirectory(list_error=expected_error)
    machine = SMBMachine(object())

    rows = await _collect(machine.list_directory(directory))

    assert rows == [(None, expected_error)]


async def test_file_and_directory_mutations_delegate_exact_arguments(
    monkeypatch,
):
    connection = object()
    machine = SMBMachine(connection)
    calls = []

    async def delete_file(received_connection, path):
        calls.append(("file", received_connection, path))
        return True, None

    async def delete_directory(received_connection, path):
        calls.append(("directory", received_connection, path))
        return True, None

    monkeypatch.setattr(
        machine_module.SMBFile,
        "delete_rempath",
        staticmethod(delete_file),
    )
    monkeypatch.setattr(
        machine_module.SMBDirectory,
        "delete_unc",
        staticmethod(delete_directory),
    )
    parent = FakeDirectory()

    assert await asyncio.wait_for(
        machine.del_file(r"\data\report.txt"), timeout=TIMEOUT
    ) == (True, None)
    assert await asyncio.wait_for(
        machine.del_directory_path(r"\\server.invalid\data\old"),
        timeout=TIMEOUT,
    ) == (True, None)
    assert await asyncio.wait_for(
        machine.create_subdirectory("new", parent), timeout=TIMEOUT
    ) == (
        True,
        None,
    )
    assert calls == [
        ("file", connection, r"\data\report.txt"),
        (
            "directory",
            connection,
            r"\\server.invalid\data\old",
        ),
    ]
    assert parent.create_calls == [("new", connection)]


@pytest.mark.xfail(
    strict=True,
    reason=(
        "KF-0612: SMBMachine.get_file_data leaves successfully opened files "
        "unclosed"
    ),
)
async def test_get_file_data_closes_file_after_iterator_completion():
    connection = object()
    smb_file = FakeReadableFile(
        [(b"first", None), (None, None)]
    )
    machine = SMBMachine(connection)

    rows = await _collect(machine.get_file_data(smb_file))

    assert rows == [(b"first", None), (None, None)]
    assert smb_file.open_calls == [(connection, "r")]
    assert smb_file.close_count == 1


@pytest.mark.xfail(
    strict=True,
    reason=(
        "KF-0613: SMBMachine.list_pipes replaces share enumeration errors "
        "with an AttributeError"
    ),
)
async def test_list_pipes_preserves_share_iterator_error():
    expected_error = RuntimeError("share enumeration failed")
    machine = SMBMachine(object())

    async def failed_shares():
        yield None, expected_error

    machine.list_shares = failed_shares

    rows = await _collect(machine.list_pipes())

    assert rows == [(None, expected_error)]


@pytest.mark.xfail(
    strict=True,
    reason=(
        "KF-0615: SMBMachine.get_file writes the (data, error) result tuple "
        "instead of its byte payload"
    ),
)
async def test_get_file_writes_payload_and_closes_file(tmp_path):
    connection = object()
    smb_file = FakeDownloadFile()
    machine = SMBMachine(connection)
    output_path = tmp_path / "download.bin"

    await asyncio.wait_for(
        machine.get_file(str(output_path), smb_file), timeout=TIMEOUT
    )

    assert output_path.read_bytes() == b"payload"
    assert smb_file.open_calls == [(connection, "r")]
    assert smb_file.close_count == 1
