"""Representative SMB2 command wire encoders and decoders."""

import struct

import pytest

from aiosmb.protocol.common import NegotiateDialects
from aiosmb.protocol.smb2.command_codes import SMB2Command
from aiosmb.protocol.smb2.commands.close import CLOSE_REPLY, CLOSE_REQ, CloseFlag
from aiosmb.protocol.smb2.commands.create import (
    CREATE_REPLY,
    CREATE_REQ,
    CreateAction,
    CreateDisposition,
    CreateOptions,
    ImpersonationLevel,
    OplockLevel,
    ShareAccess,
)
from aiosmb.protocol.smb2.commands.error import ERROR_REPLY
from aiosmb.protocol.smb2.commands.ioctl import (
    IOCTL_REPLY,
    IOCTL_REQ,
    CtlCode,
    IOCTLREQFlags,
    VALIDATE_NEGOTIATE_INFO_REQ,
)
from aiosmb.protocol.smb2.commands.negotiate import (
    NEGOTIATE_REPLY,
    NEGOTIATE_REQ,
    NegotiateCapabilities,
    NegotiateSecurityMode,
)
from aiosmb.protocol.smb2.commands.query_info import (
    QUERY_INFO_REPLY,
    QUERY_INFO_REQ,
    EaInformation,
    QueryInfoType,
    SecurityInfo,
)
from aiosmb.protocol.smb2.commands.read import (
    READ_REPLY,
    READ_REQ,
    Channel,
    ReadFlag,
)
from aiosmb.protocol.smb2.commands.sessionsetup import (
    SESSION_SETUP_REPLY,
    SESSION_SETUP_REQ,
    SessionFlags,
    SessionSetupCapabilities,
    SessionSetupFlag,
)
from aiosmb.protocol.smb2.commands.tree_connect import (
    TREE_CONNECT_REPLY,
    TREE_CONNECT_REQ,
    ShareFlags,
    ShareType,
    TreeCapabilities,
    TreeConnectFlag,
)
from aiosmb.protocol.smb2.commands.write import (
    WRITE_REPLY,
    WRITE_REQ,
    WriteFlag,
)
from aiosmb.protocol.smb2.headers.common import SMB2HeaderFlag
from aiosmb.protocol.smb2.message import SMB2Message
from aiosmb.wintypes.access_mask import FileAccessMask
from aiosmb.wintypes.dtyp.constrcuted_security.guid import GUID
from aiosmb.wintypes.fscc.FileAttributes import FileAttributes
from aiosmb.wintypes.fscc.structures.fileinfoclass import FileInfoClass
from aiosmb.wintypes.ntstatus import NTStatus


pytestmark = pytest.mark.unit


def _header(command, reply=False, status=NTStatus.SUCCESS):
    flags = SMB2HeaderFlag(0)
    if reply:
        flags |= SMB2HeaderFlag.SMB2_FLAGS_SERVER_TO_REDIR
    return struct.pack(
        "<4sHHIHHIIQIIQ16s",
        b"\xfeSMB",
        64,
        1,
        status.value,
        command.value,
        1,
        int(flags),
        0,
        42,
        0,
        7,
        9,
        b"\x00" * 16,
    )


def _message(command, body, reply=False, status=NTStatus.SUCCESS):
    return SMB2Message.from_bytes(_header(command, reply, status) + body)


def _guid(wire):
    guid = GUID()
    guid.Data1 = wire[0:4]
    guid.Data2 = wire[4:6]
    guid.Data3 = wire[6:8]
    guid.Data4 = wire[8:16]
    return guid


def test_negotiate_request_matches_golden_and_dispatches():
    guid_wire = bytes.fromhex("00112233445566778899aabbccddeeff")
    request = NEGOTIATE_REQ()
    request.SecurityMode = (
        NegotiateSecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED
    )
    request.Capabilities = NegotiateCapabilities.DFS
    request.ClientGuid = _guid(guid_wire)
    request.ClientStartTime = 0x0102030405060708
    request.Dialects = [NegotiateDialects.SMB202, NegotiateDialects.SMB210]
    golden = struct.pack(
        "<HHHHI16sQHH",
        36,
        2,
        NegotiateSecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED.value,
        0,
        NegotiateCapabilities.DFS.value,
        guid_wire,
        0x0102030405060708,
        NegotiateDialects.SMB202.value,
        NegotiateDialects.SMB210.value,
    )

    body = request.to_bytes()
    message = _message(SMB2Command.NEGOTIATE, body)

    assert body == golden
    assert isinstance(message.command, NEGOTIATE_REQ)
    assert message.command.Dialects == [
        NegotiateDialects.SMB202,
        NegotiateDialects.SMB210,
    ]
    assert message.command.ClientStartTime == 0x0102030405060708


def test_negotiate_reply_golden_vector_dispatches():
    body = struct.pack(
        "<HHHH16sIIIIQQHHI",
        65,
        NegotiateSecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED.value,
        NegotiateDialects.SMB210.value,
        0,
        bytes(range(16)),
        NegotiateCapabilities.DFS.value,
        1024 * 1024,
        512 * 1024,
        256 * 1024,
        0,
        0,
        0,
        0,
        0,
    )

    message = _message(SMB2Command.NEGOTIATE, body, reply=True)

    assert len(body) == 64
    assert isinstance(message.command, NEGOTIATE_REPLY)
    assert message.command.DialectRevision is NegotiateDialects.SMB210
    assert message.command.Capabilities == NegotiateCapabilities.DFS
    assert message.command.MaxTransactSize == 1024 * 1024
    assert message.command.MaxReadSize == 512 * 1024
    assert message.command.MaxWriteSize == 256 * 1024


def test_session_setup_request_matches_golden_and_dispatches():
    token = b"offline-token"
    request = SESSION_SETUP_REQ()
    request.Flags = SessionSetupFlag(0)
    request.SecurityMode = (
        NegotiateSecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED
    )
    request.Capabilities = SessionSetupCapabilities.SMB2_GLOBAL_CAP_DFS
    request.Channel = 0
    request.PreviousSessionId = 0
    request.Buffer = token
    golden = struct.pack(
        "<HBBIIHHQ",
        25,
        0,
        1,
        SessionSetupCapabilities.SMB2_GLOBAL_CAP_DFS.value,
        0,
        88,
        len(token),
        0,
    ) + token

    body = request.to_bytes()
    message = _message(SMB2Command.SESSION_SETUP, body)

    assert body == golden
    assert isinstance(message.command, SESSION_SETUP_REQ)
    assert message.command.Buffer == token
    assert message.command.SecurityBufferOffset == 88
    assert message.command.PreviousSessionId == b"\x00" * 8


def test_session_setup_reply_matches_golden_and_round_trips():
    token = b"challenge"
    reply = SESSION_SETUP_REPLY()
    reply.SessionFlags = SessionFlags.SMB2_SESSION_FLAG_IS_GUEST
    reply.Buffer = token
    golden = struct.pack(
        "<HHHH",
        9,
        SessionFlags.SMB2_SESSION_FLAG_IS_GUEST.value,
        72,
        len(token),
    ) + token

    body = reply.to_bytes()
    message = _message(SMB2Command.SESSION_SETUP, body, reply=True)

    assert body == golden
    assert isinstance(message.command, SESSION_SETUP_REPLY)
    assert message.command.SessionFlags == SessionFlags.SMB2_SESSION_FLAG_IS_GUEST
    assert message.command.Buffer == token
    assert message.command.to_bytes() == golden


def test_tree_connect_request_matches_golden_and_dispatches():
    path = r"\\server\share"
    encoded_path = path.encode("utf-16-le")
    request = TREE_CONNECT_REQ()
    request.Flags = TreeConnectFlag(0)
    request.Path = path
    request.Buffer = b""
    golden = struct.pack("<HHHH", 9, 0, 72, len(encoded_path)) + encoded_path

    body = request.to_bytes()
    message = _message(SMB2Command.TREE_CONNECT, body)

    assert body == golden
    assert isinstance(message.command, TREE_CONNECT_REQ)
    assert message.command.Path == path
    assert message.command.Buffer == encoded_path


def test_tree_connect_reply_matches_golden_and_round_trips():
    reply = TREE_CONNECT_REPLY()
    reply.ShareType = ShareType.DISK
    reply.ShareFlags = ShareFlags.SMB2_SHAREFLAG_DFS
    reply.Capabilities = TreeCapabilities.SMB2_SHARE_CAP_DFS
    reply.MaximalAccess = (
        FileAccessMask.FILE_READ_DATA | FileAccessMask.FILE_READ_ATTRIBUTES
    )
    golden = struct.pack(
        "<HBBIII",
        16,
        ShareType.DISK.value,
        0,
        ShareFlags.SMB2_SHAREFLAG_DFS.value,
        TreeCapabilities.SMB2_SHARE_CAP_DFS.value,
        (
            FileAccessMask.FILE_READ_DATA
            | FileAccessMask.FILE_READ_ATTRIBUTES
        ).value,
    )

    body = reply.to_bytes()
    message = _message(SMB2Command.TREE_CONNECT, body, reply=True)

    assert body == golden
    assert isinstance(message.command, TREE_CONNECT_REPLY)
    assert message.command.ShareType is ShareType.DISK
    assert message.command.ShareFlags == ShareFlags.SMB2_SHAREFLAG_DFS
    assert message.command.to_bytes() == golden


def test_create_request_name_and_fixed_fields_round_trip():
    name = "notes.txt"
    encoded_name = name.encode("utf-16-le")
    request = CREATE_REQ()
    request.RequestedOplockLevel = OplockLevel.SMB2_OPLOCK_LEVEL_NONE
    request.ImpersonationLevel = ImpersonationLevel.Impersonation
    request.DesiredAccess = FileAccessMask.GENERIC_READ
    request.FileAttributes = FileAttributes(0)
    request.ShareAccess = (
        ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE
    )
    request.CreateDisposition = CreateDisposition.FILE_OPEN
    request.CreateOptions = CreateOptions.FILE_NON_DIRECTORY_FILE
    request.Name = name
    request.CreateContext = []
    golden = (
        struct.pack(
            "<HBBIQQIIIIIHHII",
            57,
            0,
            OplockLevel.SMB2_OPLOCK_LEVEL_NONE.value,
            ImpersonationLevel.Impersonation.value,
            0,
            0,
            FileAccessMask.GENERIC_READ.value,
            0,
            (
                ShareAccess.FILE_SHARE_READ
                | ShareAccess.FILE_SHARE_WRITE
            ).value,
            CreateDisposition.FILE_OPEN.value,
            CreateOptions.FILE_NON_DIRECTORY_FILE.value,
            120,
            len(encoded_name),
            0,
            0,
        )
        + encoded_name
        + b"\x00"
    )

    body = request.to_bytes()
    message = _message(SMB2Command.CREATE, body)

    assert body == golden
    assert isinstance(message.command, CREATE_REQ)
    assert message.command.Name == name
    assert message.command.NameOffset == 120
    assert message.command.CreateContextsLength == 0


def test_create_reply_fixed_fields_round_trip():
    reply = CREATE_REPLY()
    reply.OplockLevel = OplockLevel.SMB2_OPLOCK_LEVEL_NONE
    reply.Flags = CreateOptions(0)
    reply.CreateAction = CreateAction.FILE_OPENED
    reply.CreationTime = 1
    reply.LastAccessTime = 2
    reply.LastWriteTime = 3
    reply.ChangeTime = 4
    reply.AllocationSize = 4096
    reply.EndofFile = 123
    reply.FileAttributes = FileAttributes.FILE_ATTRIBUTE_ARCHIVE
    reply.FileId = 0x00112233445566778899AABBCCDDEEFF
    reply.CreateContextsOffset = 0
    reply.CreateContextsLength = 0

    body = reply.to_bytes()
    message = _message(SMB2Command.CREATE, body, reply=True)

    assert len(body) == 88
    assert isinstance(message.command, CREATE_REPLY)
    assert message.command.CreateAction is CreateAction.FILE_OPENED
    assert message.command.FileId == reply.FileId
    assert message.command.EndofFile == 123
    assert message.command.to_bytes() == body


def test_read_request_and_reply_vectors_dispatch():
    file_id = int.from_bytes(bytes(range(16)), "little")
    request = READ_REQ()
    request.Padding = 0x50
    request.Flags = ReadFlag.SMB2_READFLAG_READ_UNBUFFERED
    request.Length = 4096
    request.Offset = 0x1020304050
    request.FileId = file_id
    request.MinimumCount = 128
    request.Channel = Channel.SMB2_CHANNEL_NONE
    request.RemainingBytes = 64
    request_body = request.to_bytes()
    request_message = _message(SMB2Command.READ, request_body)

    data = b"read-data"
    reply_body = (
        struct.pack("<HBBIII", 17, 80, 0, len(data), 3, 0) + data
    )
    reply_message = _message(SMB2Command.READ, reply_body, reply=True)

    assert len(request_body) == 49
    assert isinstance(request_message.command, READ_REQ)
    assert request_message.command.FileId == file_id
    assert request_message.command.Length == 4096
    assert request_message.command.Offset == 0x1020304050
    assert isinstance(reply_message.command, READ_REPLY)
    assert reply_message.command.DataOffset == 80
    assert reply_message.command.DataRemaining == 3
    assert reply_message.command.Buffer == data


def test_write_request_and_reply_vectors_dispatch():
    data = b"write-data"
    request = WRITE_REQ()
    request.Offset = 0x1112131415
    request.FileId = 0xFFEEDDCCBBAA99887766554433221100
    request.Channel = Channel.SMB2_CHANNEL_NONE
    request.RemainingBytes = 12
    request.Flags = WriteFlag.WRITE_THROUGH
    request.Data = data
    request_body = request.to_bytes()
    request_message = _message(SMB2Command.WRITE, request_body)

    reply_body = struct.pack("<HHIIHH", 17, 0, len(data), 0, 0, 0)
    reply_message = _message(SMB2Command.WRITE, reply_body, reply=True)

    assert request_body[:8] == struct.pack("<HHI", 49, 112, len(data))
    assert request_body[-len(data) :] == data
    assert isinstance(request_message.command, WRITE_REQ)
    assert request_message.command.Data == data
    assert request_message.command.Flags == WriteFlag.WRITE_THROUGH
    assert isinstance(reply_message.command, WRITE_REPLY)
    assert reply_message.command.Count == len(data)


def test_query_info_request_and_reply_vectors_dispatch():
    request = QUERY_INFO_REQ()
    request.InfoType = QueryInfoType.FILE
    request.FileInfoClass = FileInfoClass.FileAccessInformation
    request.OutputBufferLength = 4096
    request.AdditionalInformation = SecurityInfo(0)
    request.Flags = EaInformation(0)
    request.FileId = 0
    request_body = request.to_bytes()
    request_message = _message(SMB2Command.QUERY_INFO, request_body)

    reply = QUERY_INFO_REPLY()
    reply.Data = b"metadata"
    reply_body = reply.to_bytes()
    reply_message = _message(SMB2Command.QUERY_INFO, reply_body, reply=True)

    assert len(request_body) == 40
    assert isinstance(request_message.command, QUERY_INFO_REQ)
    assert request_message.command.InfoType is QueryInfoType.FILE
    assert (
        request_message.command.FileInfoClass
        is FileInfoClass.FileAccessInformation
    )
    assert isinstance(reply_message.command, QUERY_INFO_REPLY)
    assert reply_message.command.OutputBufferOffset == 72
    assert reply_message.command.Data == b"metadata"


def test_ioctl_validate_negotiate_request_and_pipe_wait_reply_dispatch():
    validate_payload = struct.pack(
        "<I16sHHH",
        NegotiateCapabilities.DFS.value,
        bytes(range(16)),
        NegotiateSecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED.value,
        1,
        NegotiateDialects.SMB311.value,
    )
    request = IOCTL_REQ()
    request.CtlCode = CtlCode.FSCTL_VALIDATE_NEGOTIATE_INFO
    request.FileId = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    request.MaxOutputResponse = 4096
    request.Flags = IOCTLREQFlags.IS_FSCTL
    request.Buffer = validate_payload
    request_body = request.to_bytes()
    request_message = _message(SMB2Command.IOCTL, request_body)

    reply = IOCTL_REPLY()
    reply.CtlCode = CtlCode.FSCTL_PIPE_WAIT
    reply.FileId = 0
    reply.Buffer = b""
    reply_body = reply.to_bytes()
    reply_message = _message(SMB2Command.IOCTL, reply_body, reply=True)

    assert request_body[24:32] == struct.pack("<II", 120, len(validate_payload))
    assert isinstance(request_message.command, IOCTL_REQ)
    assert isinstance(
        request_message.command.Buffer, VALIDATE_NEGOTIATE_INFO_REQ
    )
    assert request_message.command.Buffer.Dialects == [
        NegotiateDialects.SMB311
    ]
    assert isinstance(reply_message.command, IOCTL_REPLY)
    assert reply_message.command.CtlCode is CtlCode.FSCTL_PIPE_WAIT


def test_close_request_and_reply_golden_round_trips():
    request = CLOSE_REQ()
    request.Flags = CloseFlag.SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB
    request.FileId = 0x00112233445566778899AABBCCDDEEFF
    request_body = request.to_bytes()
    request_message = _message(SMB2Command.CLOSE, request_body)

    reply = CLOSE_REPLY()
    reply.Flags = CloseFlag.SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB
    reply.CreationTime = 1
    reply.LastAccessTime = 2
    reply.LastWriteTime = 3
    reply.ChangeTime = 4
    reply.AllocationSize = 4096
    reply.EndofFile = 123
    reply.FileAttributes = FileAttributes.FILE_ATTRIBUTE_ARCHIVE
    reply_body = reply.to_bytes()
    reply_message = _message(SMB2Command.CLOSE, reply_body, reply=True)

    assert request_message.command.to_bytes() == request_body
    assert isinstance(request_message.command, CLOSE_REQ)
    assert request_message.command.FileId == request.FileId
    assert reply_message.command.to_bytes() == reply_body
    assert isinstance(reply_message.command, CLOSE_REPLY)
    assert reply_message.command.EndofFile == 123


def test_error_reply_with_payload_decodes_exact_byte_count():
    body = struct.pack("<HBBI", 9, 1, 0, 5) + b"error"

    error = ERROR_REPLY.from_bytes(body)

    assert error.StructureSize == 9
    assert error.ErrorContextCount == 1
    assert error.ByteCount == 5
    assert error.ErrorData == b"error"


@pytest.mark.xfail(
    reason="KF-0205: QUERY_INFO reads InputBufferLength as 2 rather than 4 bytes",
    strict=True,
)
def test_query_info_preserves_four_byte_input_buffer_length():
    body = struct.pack(
        "<HBBIHHIII16s",
        41,
        QueryInfoType.FILE.value,
        FileInfoClass.FileAccessInformation.value,
        4096,
        0,
        0,
        65536,
        SecurityInfo.OWNER_SECURITY_INFORMATION.value,
        EaInformation.SL_RETURN_SINGLE_ENTRY.value,
        bytes(range(16)),
    )

    parsed = QUERY_INFO_REQ.from_bytes(body)

    assert parsed.InputBufferLength == 65536
