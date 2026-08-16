from __future__ import annotations

from pathlib import Path

import pytest

from aiosmb.protocol.smb2.command_codes import SMB2Command
from aiosmb.protocol.smb2.commands import (
    CLOSE_REQ,
    CREATE_REQ,
    QUERY_DIRECTORY_REQ,
    QUERY_INFO_REQ,
    READ_REQ,
    SET_INFO_REQ,
    WRITE_REQ,
    CloseFlag,
    CreateDisposition,
    CreateOptions,
    ImpersonationLevel,
    OplockLevel,
    QueryDirectoryFlag,
    QueryInfoType,
    ShareAccess,
)
from aiosmb.protocol.smb2.message import SMB2Message
from aiosmb.wintypes.access_mask import FileAccessMask
from aiosmb.wintypes.fscc.FileAttributes import FileAttributes
from aiosmb.wintypes.fscc.structures.FileEndOfFileInformation import (
    FileEndOfFileInformation,
)
from aiosmb.wintypes.fscc.structures.FileRenameInformation import (
    FileRenameInformation,
)
from aiosmb.wintypes.fscc.structures.FileStandardInformation import (
    FileStandardInformation,
)
from aiosmb.wintypes.fscc.structures.fileinfoclass import FileInfoClass
from aiosmb.wintypes.ntstatus import NTStatus
from tests.component.server_relay.support import make_request, wait_for
from tests.component.server_relay.test_smb202_server import (
    connect_tree,
    make_connection,
)


pytestmark = [pytest.mark.component, pytest.mark.asyncio]


def create_request(
    name: str,
    disposition: CreateDisposition,
    options: CreateOptions = CreateOptions.FILE_NON_DIRECTORY_FILE,
) -> CREATE_REQ:
    request = CREATE_REQ()
    request.RequestedOplockLevel = OplockLevel.SMB2_OPLOCK_LEVEL_NONE
    request.ImpersonationLevel = ImpersonationLevel.Impersonation
    request.DesiredAccess = (
        FileAccessMask.GENERIC_READ
        | FileAccessMask.GENERIC_WRITE
        | FileAccessMask.DELETE
    )
    request.FileAttributes = FileAttributes(0)
    request.ShareAccess = (
        ShareAccess.FILE_SHARE_READ
        | ShareAccess.FILE_SHARE_WRITE
        | ShareAccess.FILE_SHARE_DELETE
    )
    request.CreateDisposition = disposition
    request.CreateOptions = options
    request.Name = name
    return request


async def send(connection, transport, command, code, tree_id, message_id):
    await wait_for(
        getattr(connection, code.name.lower())(
            make_request(
                command,
                code,
                message_id=message_id,
                tree_id=tree_id,
            )
        )
    )
    return SMB2Message.from_bytes(transport.writes[-1])


async def test_file_crud_rename_truncate_and_delete(tmp_path: Path) -> None:
    connection, transport, _ = make_connection({"data": tmp_path})
    tree_id = await connect_tree(connection, transport, r"\\server\data")

    created = await send(
        connection,
        transport,
        create_request("upload.bin", CreateDisposition.FILE_OPEN_IF),
        SMB2Command.CREATE,
        tree_id,
        10,
    )
    assert created.header.Status == NTStatus.SUCCESS
    file_id = created.command.FileId

    write = WRITE_REQ()
    write.Offset = 0
    write.FileId = file_id
    write.Data = b"abcdef"
    written = await send(
        connection, transport, write, SMB2Command.WRITE, tree_id, 11
    )
    assert written.command.Count == 6

    read = READ_REQ()
    read.Length = 6
    read.Offset = 0
    read.FileId = file_id
    read.MinimumCount = 0
    fetched = await send(
        connection, transport, read, SMB2Command.READ, tree_id, 12
    )
    assert fetched.command.Buffer == b"abcdef"

    query = QUERY_INFO_REQ()
    query.InfoType = QueryInfoType.FILE
    query.FileInfoClass = FileInfoClass.FileStandardInformation
    query.OutputBufferLength = 1024
    query.FileId = file_id
    queried = await send(
        connection, transport, query, SMB2Command.QUERY_INFO, tree_id, 13
    )
    standard = FileStandardInformation.from_bytes(queried.command.Data)
    assert standard.EndOfFile == 6

    eof = FileEndOfFileInformation()
    eof.EndOfFile = 3
    set_eof = SET_INFO_REQ()
    set_eof.InfoType = QueryInfoType.FILE
    set_eof.FileInfoClass = FileInfoClass.FileEndOfFileInformation
    set_eof.FileId = file_id
    set_eof.Data = eof
    truncated = await send(
        connection, transport, set_eof, SMB2Command.SET_INFO, tree_id, 14
    )
    assert truncated.header.Status == NTStatus.SUCCESS

    rename = FileRenameInformation()
    rename.FileName = "renamed.bin"
    set_rename = SET_INFO_REQ()
    set_rename.InfoType = QueryInfoType.FILE
    set_rename.FileInfoClass = FileInfoClass.FileRenameInformation
    set_rename.FileId = file_id
    set_rename.Data = rename
    renamed = await send(
        connection, transport, set_rename, SMB2Command.SET_INFO, tree_id, 15
    )
    assert renamed.header.Status == NTStatus.SUCCESS

    close = CLOSE_REQ()
    close.Flags = CloseFlag.NONE
    close.FileId = file_id
    closed = await send(
        connection, transport, close, SMB2Command.CLOSE, tree_id, 16
    )
    assert closed.header.Status == NTStatus.SUCCESS
    assert (tmp_path / "renamed.bin").read_bytes() == b"abc"

    delete_open = create_request(
        "renamed.bin",
        CreateDisposition.FILE_OPEN,
        CreateOptions.FILE_NON_DIRECTORY_FILE
        | CreateOptions.FILE_DELETE_ON_CLOSE,
    )
    deleted = await send(
        connection,
        transport,
        delete_open,
        SMB2Command.CREATE,
        tree_id,
        17,
    )
    close.FileId = deleted.command.FileId
    await send(connection, transport, close, SMB2Command.CLOSE, tree_id, 18)
    assert not (tmp_path / "renamed.bin").exists()


async def test_directory_create_enumerate_and_remove(tmp_path: Path) -> None:
    connection, transport, _ = make_connection({"data": tmp_path})
    tree_id = await connect_tree(connection, transport, r"\\server\data")
    directory = await send(
        connection,
        transport,
        create_request(
            "folder",
            CreateDisposition.FILE_CREATE,
            CreateOptions.FILE_DIRECTORY_FILE,
        ),
        SMB2Command.CREATE,
        tree_id,
        20,
    )
    directory_id = directory.command.FileId
    (tmp_path / "folder" / "entry.txt").write_text("x", encoding="utf-8")

    query = QUERY_DIRECTORY_REQ()
    query.FileInformationClass = FileInfoClass.FileFullDirectoryInformation
    query.Flags = QueryDirectoryFlag.SMB2_RESTART_SCANS
    query.FileIndex = 0
    query.FileId = directory_id
    query.FileName = "*"
    query.OutputBufferLength = 4096
    listed = await send(
        connection,
        transport,
        query,
        SMB2Command.QUERY_DIRECTORY,
        tree_id,
        21,
    )
    assert "entry.txt".encode("utf-16-le") in listed.command.Data


async def test_create_rejects_share_escape(tmp_path: Path) -> None:
    connection, transport, _ = make_connection({"data": tmp_path})
    tree_id = await connect_tree(connection, transport, r"\\server\data")
    escaped = await send(
        connection,
        transport,
        create_request(r"..\escape", CreateDisposition.FILE_OPEN_IF),
        SMB2Command.CREATE,
        tree_id,
        30,
    )
    assert escaped.header.Status == NTStatus.ACCESS_DENIED
