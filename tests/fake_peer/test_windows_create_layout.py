"""Scripted peer that rejects the CREATE layouts Windows 2019 rejected.

Unit goldens generated from ``to_bytes()`` cannot catch this. The peer
inspects the raw CREATE body with numeric Windows rules and only then
returns SUCCESS. ``SMBConnection.create`` must therefore emit the
share-root layout that a real file server accepted.
"""

from __future__ import annotations

import asyncio

import pytest

from aiosmb.commons.exceptions import SMBException
from aiosmb.protocol.smb2.command_codes import SMB2Command
from aiosmb.protocol.smb2.commands import (
    CREATE_REPLY,
    ERROR_REPLY,
    TREE_CONNECT_REPLY,
)
from aiosmb.protocol.smb2.commands.create import (
    CreateAction,
    CreateDisposition,
    CreateOptions,
    OplockLevel,
    ShareAccess,
)
from aiosmb.protocol.smb2.commands.tree_connect import (
    ShareFlags,
    ShareType,
    TreeCapabilities,
)
from aiosmb.protocol.smb2.message import SMB2Message
from aiosmb.wintypes.access_mask import FileAccessMask
from aiosmb.wintypes.fscc.FileAttributes import FileAttributes
from aiosmb.wintypes.ntstatus import NTStatus
from tests.support.scripted_smb import ScriptedSMBTransport, connection_reader
from tests.support.smb_connection import make_connection, make_reply
from tests.support.smb_wire import (
    command_body_from_smb2_message,
    windows_create_layout_errors,
)


pytestmark = [pytest.mark.fake_peer, pytest.mark.asyncio]
TIMEOUT = 0.75


def _tree_reply(message_id: int, tree_id: int, session_id: int) -> bytes:
    body = TREE_CONNECT_REPLY()
    body.ShareType = ShareType.DISK
    body.ShareFlags = ShareFlags.SMB2_SHAREFLAG_MANUAL_CACHING
    body.Capabilities = TreeCapabilities.SMB2_SHARE_CAP_NONE
    body.MaximalAccess = FileAccessMask.GENERIC_READ
    return make_reply(
        message_id,
        body,
        command=SMB2Command.TREE_CONNECT,
        tree_id=tree_id,
        session_id=session_id,
    ).to_bytes()


def _create_ok(
    message_id: int, tree_id: int, session_id: int, file_id: int
) -> bytes:
    body = CREATE_REPLY()
    body.OplockLevel = OplockLevel.SMB2_OPLOCK_LEVEL_NONE
    body.Flags = CreateOptions(0)
    body.CreateAction = CreateAction.FILE_OPENED
    body.CreationTime = 0
    body.LastAccessTime = 0
    body.LastWriteTime = 0
    body.ChangeTime = 0
    body.AllocationSize = 4096
    body.EndofFile = 0
    body.FileAttributes = FileAttributes.FILE_ATTRIBUTE_DIRECTORY
    body.FileId = file_id
    return make_reply(
        message_id,
        body,
        command=SMB2Command.CREATE,
        tree_id=tree_id,
        session_id=session_id,
    ).to_bytes()


def _invalid_parameter(
    message_id: int, tree_id: int, session_id: int
) -> bytes:
    return make_reply(
        message_id,
        ERROR_REPLY(),
        command=SMB2Command.CREATE,
        status=NTStatus.INVALID_PARAMETER,
        tree_id=tree_id,
        session_id=session_id,
    ).to_bytes()


def _windows_create_peer(connection, tree_id: int, file_ids):
    ids = iter(file_ids)

    def respond(wire_data: bytes, transport: ScriptedSMBTransport) -> bytes:
        request = SMB2Message.from_bytes(wire_data)
        message_id = request.header.MessageId
        if request.header.Command == SMB2Command.TREE_CONNECT:
            return _tree_reply(message_id, tree_id, connection.SessionId)
        if request.header.Command != SMB2Command.CREATE:
            raise AssertionError(
                "unexpected scripted command: {!r}".format(
                    request.header.Command
                )
            )
        errors = windows_create_layout_errors(
            command_body_from_smb2_message(wire_data)
        )
        if errors:
            return _invalid_parameter(
                message_id, tree_id, connection.SessionId
            )
        return _create_ok(
            message_id,
            tree_id,
            connection.SessionId,
            next(ids),
        )

    return respond


async def test_connection_create_empty_name_survives_windows_layout_peer() -> None:
    connection = make_connection()
    connection.SessionId = 0xABC
    tree_id = 0x11
    root_id = 0x11112222333344445555666677778888
    file_id = 0x9999AAAABBBBCCCCDDDDEEEEFFFF0000
    transport = ScriptedSMBTransport(
        [_windows_create_peer(connection, tree_id, (root_id, file_id))] * 3
    )

    async with connection_reader(connection, transport):
        tree, error = await asyncio.wait_for(
            connection.tree_connect(r"\\fake-peer.invalid\NETLOGON"),
            timeout=TIMEOUT,
        )
        assert error is None

        handle, error = await asyncio.wait_for(
            connection.create(
                tree.tree_id,
                "",
                FileAccessMask.FILE_READ_DATA,
                ShareAccess.FILE_SHARE_READ,
                CreateOptions.FILE_DIRECTORY_FILE
                | CreateOptions.FILE_SYNCHRONOUS_IO_NONALERT,
                CreateDisposition.FILE_OPEN,
                0,
            ),
            timeout=TIMEOUT,
        )
        assert error is None
        assert handle == root_id

        handle, error = await asyncio.wait_for(
            connection.create(
                tree.tree_id,
                "policy",
                FileAccessMask.FILE_READ_DATA,
                ShareAccess.FILE_SHARE_READ,
                CreateOptions.FILE_DIRECTORY_FILE,
                CreateDisposition.FILE_OPEN,
                0,
            ),
            timeout=TIMEOUT,
        )
        assert error is None
        assert handle == file_id


async def test_windows_layout_peer_rejects_name_offset_zero() -> None:
    connection = make_connection()
    connection.SessionId = 0xABC
    tree_id = 0x22
    seen = []

    def respond(wire_data: bytes, transport: ScriptedSMBTransport) -> bytes:
        request = SMB2Message.from_bytes(wire_data)
        if request.header.Command == SMB2Command.TREE_CONNECT:
            return _tree_reply(
                request.header.MessageId, tree_id, connection.SessionId
            )
        body = bytearray(command_body_from_smb2_message(wire_data))
        body[44:46] = b"\x00\x00"
        seen.extend(windows_create_layout_errors(bytes(body)))
        return _invalid_parameter(
            request.header.MessageId, tree_id, connection.SessionId
        )

    transport = ScriptedSMBTransport([respond, respond])
    async with connection_reader(connection, transport):
        tree, error = await asyncio.wait_for(
            connection.tree_connect(r"\\fake-peer.invalid\SYSVOL"),
            timeout=TIMEOUT,
        )
        assert error is None
        handle, error = await asyncio.wait_for(
            connection.create(
                tree.tree_id,
                "",
                FileAccessMask.FILE_READ_DATA,
                ShareAccess.FILE_SHARE_READ,
                CreateOptions.FILE_DIRECTORY_FILE,
                CreateDisposition.FILE_OPEN,
                0,
            ),
            timeout=TIMEOUT,
        )
        assert handle is None
        assert isinstance(error, SMBException)
        assert error.ntstatus == NTStatus.INVALID_PARAMETER
    assert any("NameOffset" in item for item in seen)
