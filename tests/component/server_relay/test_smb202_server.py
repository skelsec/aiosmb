"""Supported SMB 2.0.2 server paths over an in-process transport."""

from __future__ import annotations

import asyncio
import importlib
import sys
from pathlib import Path
from typing import Any, Dict, Tuple

import pytest

from aiosmb.protocol.common import NegotiateDialects
from aiosmb.protocol.smb2.command_codes import SMB2Command
from aiosmb.protocol.smb2.commands import (
    CLOSE_REQ,
    CREATE_REQ,
    ECHO_REQ,
    IOCTL_REQ,
    QUERY_DIRECTORY_REQ,
    TREE_CONNECT_REQ,
)
from aiosmb.protocol.smb2.commands.close import CloseFlag
from aiosmb.protocol.smb2.commands.query_directory import QueryDirectoryFlag
from aiosmb.protocol.smb2.message import SMB2Message
from aiosmb.wintypes.fscc.structures.FileFullDirectoryInformation import (
    FileFullDirectoryInformationList,
)
from aiosmb.wintypes.fscc.structures.fileinfoclass import FileInfoClass
from aiosmb.wintypes.ntstatus import NTStatus
from tests.component.server_relay.support import (
    FakeGSSAPI,
    FakeTransport,
    make_request,
    settle_cancelled,
    wait_for,
)


pytestmark = [pytest.mark.component, pytest.mark.asyncio]


def server_types() -> Tuple[Any, Any]:
    try:
        server_module = importlib.import_module("aiosmb.server.server")
        connection_module = importlib.import_module(
            "aiosmb.server.serverconnection"
        )
    except TypeError:
        if sys.version_info < (3, 9):
            pytest.xfail(
                "blocked by KF-0632: server annotations require Python 3.9"
            )
        raise
    return server_module, connection_module


def make_connection(
    shares: Dict[str, Path] = None,
) -> Tuple[SMBServerConnection, FakeTransport, FakeGSSAPI]:
    server_module, connection_module = server_types()
    transport = FakeTransport()
    gssapi = FakeGSSAPI()
    settings = server_module.SMBServerSettings(
        lambda: gssapi, log_callback=None
    )
    settings.shares = {
        name: str(path) for name, path in (shares or {}).items()
    }
    connection = connection_module.SMBServerConnection(
        settings, transport, connection_id=11
    )
    return connection, transport, gssapi


async def connect_tree(
    connection: SMBServerConnection,
    transport: FakeTransport,
    path: str,
    message_id: int = 17,
) -> int:
    request = TREE_CONNECT_REQ()
    request.Path = path
    connection.status = connection.status.__class__.RUNNING
    await wait_for(
        connection.tree_connect(
            make_request(
                request,
                SMB2Command.TREE_CONNECT,
                message_id=message_id,
            )
        )
    )
    reply = SMB2Message.from_bytes(transport.writes[-1])
    assert reply.header.Status == NTStatus.SUCCESS
    return reply.header.TreeId


def query_request(
    tree_id: int,
    flags: QueryDirectoryFlag = QueryDirectoryFlag.SMB2_RESTART_SCANS,
    pattern: str = "*",
    output_length: int = 65535,
) -> SMB2Message:
    command = QUERY_DIRECTORY_REQ()
    command.FileInformationClass = FileInfoClass.FileFullDirectoryInformation
    command.Flags = flags
    command.FileIndex = 0
    command.FileId = 0
    command.FileName = pattern
    command.OutputBufferLength = output_length
    return make_request(
        command,
        SMB2Command.QUERY_DIRECTORY,
        message_id=43,
        tree_id=tree_id,
    )


async def test_smb202_negotiate_uses_server_settings() -> None:
    connection, transport, gssapi = make_connection()
    connection.settings.MaxReadSize = 0x20000
    connection.MaxReadSize = connection.settings.MaxReadSize

    await wait_for(
        connection.negotiate(
            make_request(ECHO_REQ(), SMB2Command.NEGOTIATE, message_id=9)
        )
    )

    reply = SMB2Message.from_bytes(transport.writes[0])
    assert reply.header.Command == SMB2Command.NEGOTIATE
    assert reply.header.Status == NTStatus.SUCCESS
    assert reply.command.DialectRevision == NegotiateDialects.SMB202
    assert reply.command.MaxReadSize == 0x20000
    assert reply.command.Buffer == gssapi.get_mechtypes_list()
    assert connection.selected_dialect == NegotiateDialects.SMB202
    assert connection.SupportsMultiCredit is True
    assert connection.status == connection.status.__class__.SESSIONSETUP


async def test_echo_returns_a_successful_smb202_response() -> None:
    connection, transport, _ = make_connection()
    connection.status = connection.status.__class__.RUNNING
    connection.SessionId = 0x3344
    request = make_request(
        ECHO_REQ(),
        SMB2Command.ECHO,
        message_id=0,
        credit_charge=3,
        credit_request=5,
    )

    await wait_for(connection.echo(request))

    reply = SMB2Message.from_bytes(transport.writes[0])
    assert reply.header.Command == SMB2Command.ECHO
    assert reply.header.Status == NTStatus.SUCCESS
    assert reply.header.SessionId == connection.SessionId
    assert reply.header.CreditCharge == 3
    assert reply.header.CreditReq == 5


@pytest.mark.xfail(
    strict=True,
    reason="KF-0620: server responses replace the client MessageId",
)
async def test_response_preserves_client_message_id() -> None:
    connection, transport, _ = make_connection()
    connection.status = connection.status.__class__.RUNNING
    request = make_request(ECHO_REQ(), SMB2Command.ECHO, message_id=81)

    await wait_for(connection.echo(request))

    reply = SMB2Message.from_bytes(transport.writes[0])
    assert reply.header.MessageId == 81


async def test_tree_connect_maps_share_names_case_insensitively(
    tmp_path: Path,
) -> None:
    connection, transport, _ = make_connection({"Data": tmp_path})

    tree_id = await connect_tree(
        connection, transport, r"\\server.invalid\dAtA"
    )

    reply = SMB2Message.from_bytes(transport.writes[-1])
    tree = connection._SMBServerConnection__treeid_to_entry[tree_id]
    assert tree.path == tmp_path
    assert reply.command.ShareType.name == "DISK"
    assert tree_id > 0


async def test_unknown_share_returns_bad_network_name(tmp_path: Path) -> None:
    connection, transport, _ = make_connection({"data": tmp_path})
    request = TREE_CONNECT_REQ()
    request.Path = r"\\server.invalid\missing"
    connection.status = connection.status.__class__.RUNNING

    await wait_for(
        connection.tree_connect(
            make_request(request, SMB2Command.TREE_CONNECT, message_id=19)
        )
    )

    reply = SMB2Message.from_bytes(transport.writes[-1])
    assert reply.header.Status == NTStatus.BAD_NETWORK_NAME
    assert reply.header.TreeId == 0


async def test_root_create_query_and_close_supported_path(
    tmp_path: Path,
) -> None:
    (tmp_path / "alpha.txt").write_text("alpha", encoding="utf-8")
    (tmp_path / "nested").mkdir()
    connection, transport, _ = make_connection({"data": tmp_path})
    tree_id = await connect_tree(
        connection, transport, r"\\server.invalid\data"
    )

    create = CREATE_REQ()
    create.Name = None
    await wait_for(
        connection.create(
            make_request(
                create,
                SMB2Command.CREATE,
                message_id=23,
                tree_id=tree_id,
            )
        )
    )
    create_reply = SMB2Message.from_bytes(transport.writes[-1])
    assert create_reply.header.Status == NTStatus.SUCCESS
    assert create_reply.command.FileId == 0
    assert create_reply.command.FileAttributes.name == (
        "FILE_ATTRIBUTE_DIRECTORY"
    )

    await wait_for(
        connection.query_directory(query_request(tree_id, pattern="*"))
    )
    query_reply = SMB2Message.from_bytes(transport.writes[-1])
    entries = FileFullDirectoryInformationList.from_bytes(
        query_reply.command.Data
    )
    assert query_reply.header.Status == NTStatus.SUCCESS
    assert {entry.FileName for entry in entries} == {"alpha.txt", "nested"}

    continuation = query_request(
        tree_id, flags=QueryDirectoryFlag(0), pattern="*"
    )
    await wait_for(connection.query_directory(continuation))
    exhausted = SMB2Message.from_bytes(transport.writes[-1])
    assert exhausted.header.Status == NTStatus.NO_MORE_FILES

    close = CLOSE_REQ()
    close.Flags = CloseFlag.NONE
    close.FileId = 0
    await wait_for(
        connection.close(
            make_request(
                close,
                SMB2Command.CLOSE,
                message_id=29,
                tree_id=tree_id,
            )
        )
    )
    close_reply = SMB2Message.from_bytes(transport.writes[-1])
    assert close_reply.header.Status == NTStatus.SUCCESS
    assert close_reply.header.Command == SMB2Command.CLOSE


async def test_close_releases_a_tracked_file_handle(tmp_path: Path) -> None:
    file_path = tmp_path / "tracked.txt"
    file_path.write_bytes(b"tracked")
    connection, transport, _ = make_connection({"data": tmp_path})
    tree_id = await connect_tree(
        connection, transport, r"\\server.invalid\data"
    )
    tree = connection._SMBServerConnection__treeid_to_entry[tree_id]
    handle = file_path.open("rb")
    _, connection_module = server_types()
    tree.file_entries[71] = connection_module.FileEntry(
        file_id=71, path=file_path, handle=handle
    )
    close = CLOSE_REQ()
    close.Flags = CloseFlag.SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB
    close.FileId = 71

    await wait_for(
        connection.close(
            make_request(
                close,
                SMB2Command.CLOSE,
                message_id=31,
                tree_id=tree_id,
            )
        )
    )

    reply = SMB2Message.from_bytes(transport.writes[-1])
    assert handle.closed is True
    assert 71 not in tree.file_entries
    assert reply.header.Status == NTStatus.SUCCESS
    assert reply.command.EndofFile == len(b"tracked")


@pytest.mark.xfail(
    strict=True,
    reason="KF-0621: relative existing-file CREATE produces no response",
)
async def test_existing_file_create_accepts_a_share_relative_name(
    tmp_path: Path,
) -> None:
    (tmp_path / "alpha.txt").write_bytes(b"alpha")
    connection, transport, _ = make_connection({"data": tmp_path})
    tree_id = await connect_tree(
        connection, transport, r"\\server.invalid\data"
    )
    writes_before = len(transport.writes)
    create = CREATE_REQ()
    create.Name = "alpha.txt"

    await wait_for(
        connection.create(
            make_request(
                create,
                SMB2Command.CREATE,
                message_id=47,
                tree_id=tree_id,
            )
        )
    )

    assert len(transport.writes) == writes_before + 1
    reply = SMB2Message.from_bytes(transport.writes[-1])
    assert reply.header.Status == NTStatus.SUCCESS
    assert reply.command.EndofFile == 5


@pytest.mark.xfail(
    strict=True,
    reason="KF-0622: QUERY_DIRECTORY ignores SMB2_RETURN_SINGLE_ENTRY",
)
async def test_query_directory_honors_return_single_entry(
    tmp_path: Path,
) -> None:
    (tmp_path / "one.txt").write_bytes(b"1")
    (tmp_path / "two.txt").write_bytes(b"2")
    connection, transport, _ = make_connection({"data": tmp_path})
    tree_id = await connect_tree(
        connection, transport, r"\\server.invalid\data"
    )
    request = query_request(
        tree_id,
        flags=(
            QueryDirectoryFlag.SMB2_RESTART_SCANS
            | QueryDirectoryFlag.SMB2_RETURN_SINGLE_ENTRY
        ),
    )

    await wait_for(connection.query_directory(request))

    reply = SMB2Message.from_bytes(transport.writes[-1])
    entries = FileFullDirectoryInformationList.from_bytes(reply.command.Data)
    assert len(entries) == 1


@pytest.mark.xfail(
    strict=True,
    reason="KF-0623: CLOSE reports success for an unknown FileId",
)
async def test_close_rejects_an_unknown_file_id(tmp_path: Path) -> None:
    connection, transport, _ = make_connection({"data": tmp_path})
    tree_id = await connect_tree(
        connection, transport, r"\\server.invalid\data"
    )
    close = CLOSE_REQ()
    close.Flags = CloseFlag.NONE
    close.FileId = 0xDEADBEEF

    await wait_for(
        connection.close(
            make_request(
                close,
                SMB2Command.CLOSE,
                message_id=53,
                tree_id=tree_id,
            )
        )
    )

    reply = SMB2Message.from_bytes(transport.writes[-1])
    assert reply.header.Status == NTStatus.INVALID_HANDLE


@pytest.mark.parametrize(
    "command,handler_name",
    (
        (SMB2Command.TREE_CONNECT, "tree_connect"),
        (SMB2Command.CREATE, "create"),
        (SMB2Command.IOCTL, "ioctl"),
        (SMB2Command.ECHO, "echo"),
        (SMB2Command.QUERY_DIRECTORY, "query_directory"),
        (SMB2Command.CLOSE, "close"),
    ),
)
async def test_running_reader_dispatches_supported_commands(
    command: SMB2Command,
    handler_name: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = make_request(ECHO_REQ(), command, message_id=61)
    transport = FakeTransport([b"\xfe"])
    connection, _, _ = make_connection()
    connection.connection = transport
    connection.status = connection.status.__class__.RUNNING
    observed = []
    dispatched = asyncio.Event()

    async def handler(message: SMB2Message) -> None:
        observed.append(message)
        dispatched.set()

    monkeypatch.setattr(
        "aiosmb.server.serverconnection.SMB2Message.from_bytes",
        lambda data: request,
    )
    monkeypatch.setattr(connection, handler_name, handler)
    task = await connection.run()
    await wait_for(dispatched.wait())
    await settle_cancelled(task)

    assert observed == [request]


async def test_reader_clears_completed_pending_lifecycle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class PendingProbe:
        def __init__(self) -> None:
            self.stop_calls = 0

        async def stop(self) -> None:
            self.stop_calls += 1

    request = make_request(ECHO_REQ(), SMB2Command.ECHO, message_id=73)
    transport = FakeTransport([b"\xfe"])
    connection, _, _ = make_connection()
    connection.connection = transport
    connection.status = connection.status.__class__.RUNNING
    pending = PendingProbe()
    connection.pending_table[73] = pending
    dispatched = asyncio.Event()

    async def echo(message: SMB2Message) -> None:
        dispatched.set()

    monkeypatch.setattr(
        "aiosmb.server.serverconnection.SMB2Message.from_bytes",
        lambda data: request,
    )
    monkeypatch.setattr(connection, "echo", echo)
    task = await connection.run()
    await wait_for(dispatched.wait())
    await asyncio.sleep(0)
    await settle_cancelled(task)

    assert pending.stop_calls == 1
    assert connection.pending_table == {}


@pytest.mark.xfail(
    strict=True,
    reason="KF-0626: receive-loop EOF leaves server status RUNNING",
)
async def test_reader_eof_transitions_server_connection_to_closed() -> None:
    connection, transport, _ = make_connection()
    status_class = connection.status.__class__
    connection.status = status_class.RUNNING
    task = await connection.run()

    await settle_cancelled(task)

    assert connection.status == status_class.CLOSED
    assert transport.closed is True


@pytest.mark.xfail(
    strict=True,
    reason="KF-0627: connection stop leaks tracked filesystem handles",
)
async def test_connection_stop_closes_tracked_file_handles(
    tmp_path: Path,
) -> None:
    file_path = tmp_path / "leaked.txt"
    file_path.write_bytes(b"data")
    connection, _, _ = make_connection({"data": tmp_path})
    tree_id = await connect_tree(
        connection, connection.connection, r"\\server.invalid\data"
    )
    tree = connection._SMBServerConnection__treeid_to_entry[tree_id]
    handle = file_path.open("rb")
    _, connection_module = server_types()
    tree.file_entries[5] = connection_module.FileEntry(
        file_id=5, path=file_path, handle=handle
    )

    try:
        await wait_for(connection.stop())
        assert handle.closed is True
    finally:
        handle.close()
