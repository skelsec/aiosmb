"""Encoder/decoder invariants that golden-from-to_bytes tests cannot catch.

The share-root CREATE regression set NameOffset=0 for an empty name. Windows
2019 answered STATUS_INVALID_PARAMETER. The older codec tests only encoded a
named file and compared the result to itself, so the bad empty-name layout
never failed.

These cases pin numeric offsets, StructureSize-vs-body length, UTF-16
alignment, and round-trips through SMB2Message. Expected bytes are packed
with struct, not copied from ``to_bytes()``.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from aiosmb.protocol.smb2.command_codes import SMB2Command
from aiosmb.protocol.smb2.commands.close import CLOSE_REQ, CloseFlag
from aiosmb.protocol.smb2.commands.create import (
    CREATE_CONTEXT,
    CREATE_REPLY,
    CREATE_REQ,
    CREATE_TIMEWARP_TOKEN,
    CreateAction,
    CreateDisposition,
    CreateOptions,
    CreateReplyFlag,
    ImpersonationLevel,
    OplockLevel,
    ShareAccess,
)
from aiosmb.protocol.smb2.commands.ioctl import (
    IOCTL_REQ,
    CtlCode,
    IOCTLREQFlags,
)
from aiosmb.protocol.smb2.commands.negotiate import (
    NegotiateCapabilities,
    NegotiateSecurityMode,
)
from aiosmb.protocol.smb2.commands.query_directory import (
    QUERY_DIRECTORY_REQ,
    QueryDirectoryFlag,
)
from aiosmb.protocol.smb2.commands.query_info import (
    QUERY_INFO_REQ,
    EaInformation,
    QueryInfoType,
    SecurityInfo,
)
from aiosmb.protocol.smb2.commands.read import READ_REQ, Channel, ReadFlag
from aiosmb.protocol.smb2.commands.sessionsetup import (
    SESSION_SETUP_REQ,
    SessionSetupCapabilities,
    SessionSetupFlag,
)
from aiosmb.protocol.smb2.commands.set_info import SET_INFO_REQ
from aiosmb.protocol.smb2.commands.tree_connect import (
    TREE_CONNECT_REQ,
    TreeConnectFlag,
)
from aiosmb.protocol.smb2.commands.write import WRITE_REQ, WriteFlag
from aiosmb.protocol.smb2.headers.common import SMB2HeaderFlag
from aiosmb.protocol.smb2.message import SMB2Message
from aiosmb.wintypes.access_mask import FileAccessMask
from aiosmb.wintypes.fscc.FileAttributes import FileAttributes
from aiosmb.wintypes.fscc.structures.fileinfoclass import FileInfoClass
from aiosmb.wintypes.ntstatus import NTStatus
from tests.support.smb_wire import (
    SMB2_HEADER_SIZE,
    WINDOWS_EMPTY_CREATE_MIN_BODY,
    WINDOWS_EMPTY_CREATE_NAME_OFFSET,
    command_body_from_smb2_message,
    create_name_fields,
    smb2_relative_range,
    windows_create_layout_errors,
)


pytestmark = pytest.mark.unit


def _header(command, reply=False):
    flags = SMB2HeaderFlag(0)
    if reply:
        flags |= SMB2HeaderFlag.SMB2_FLAGS_SERVER_TO_REDIR
    return struct.pack(
        "<4sHHIHHIIQIIQ16s",
        b"\xfeSMB",
        64,
        1,
        0,
        command.value,
        1,
        int(flags),
        0,
        7,
        0,
        3,
        5,
        b"\x00" * 16,
    )


def _message(command, body, reply=False):
    return SMB2Message.from_bytes(_header(command, reply) + body)


def _create_like_connection(
    file_path,
    desired_access=FileAccessMask.FILE_READ_DATA,
    share_mode=ShareAccess.FILE_SHARE_READ,
    create_options=CreateOptions.FILE_DIRECTORY_FILE
    | CreateOptions.FILE_SYNCHRONOUS_IO_NONALERT,
    create_disposition=CreateDisposition.FILE_OPEN,
    file_attrs=0,
    create_contexts=None,
):
    # Field assignments must stay aligned with SMBConnection.create.
    command = CREATE_REQ()
    command.RequestedOplockLevel = OplockLevel.SMB2_OPLOCK_LEVEL_NONE
    command.ImpersonationLevel = ImpersonationLevel.Impersonation
    command.DesiredAccess = desired_access
    command.FileAttributes = file_attrs
    command.ShareAccess = share_mode
    command.CreateDisposition = create_disposition
    command.CreateOptions = create_options
    command.Name = file_path
    command.CreateContext = create_contexts
    return command


def test_share_root_create_matches_windows_accepted_layout():
    body = _create_like_connection("").to_bytes()
    name_offset, name_length, ctx_offset, ctx_length = create_name_fields(body)

    assert windows_create_layout_errors(body) == []
    assert int.from_bytes(body[0:2], "little") == 57
    assert name_offset == WINDOWS_EMPTY_CREATE_NAME_OFFSET
    assert name_length == 0
    assert ctx_offset == 0
    assert ctx_length == 0
    assert len(body) == WINDOWS_EMPTY_CREATE_MIN_BODY
    assert body[40:44] == struct.pack(
        "<I",
        (
            CreateOptions.FILE_DIRECTORY_FILE
            | CreateOptions.FILE_SYNCHRONOUS_IO_NONALERT
        ).value,
    )


@pytest.mark.parametrize("name", ["", None])
def test_empty_and_missing_create_name_use_the_same_windows_layout(name):
    body = _create_like_connection(name).to_bytes()

    assert windows_create_layout_errors(body) == []
    assert create_name_fields(body)[0] == WINDOWS_EMPTY_CREATE_NAME_OFFSET
    assert len(body) == WINDOWS_EMPTY_CREATE_MIN_BODY


def test_windows_rejected_empty_create_layouts_are_documented():
    accepted = _create_like_connection("").to_bytes()
    name_offset_zero = bytearray(accepted)
    name_offset_zero[44:46] = struct.pack("<H", 0)
    truncated = accepted[:56]

    assert windows_create_layout_errors(bytes(name_offset_zero))
    assert windows_create_layout_errors(truncated)
    assert windows_create_layout_errors(accepted) == []


def test_share_root_create_round_trips_through_message_dispatch():
    body = _create_like_connection("").to_bytes()
    message = _message(SMB2Command.CREATE, body)
    parsed = message.command

    assert isinstance(parsed, CREATE_REQ)
    assert parsed.NameOffset == WINDOWS_EMPTY_CREATE_NAME_OFFSET
    assert parsed.NameLength == 0
    assert parsed.Name is None
    assert parsed.CreateOptions == (
        CreateOptions.FILE_DIRECTORY_FILE
        | CreateOptions.FILE_SYNCHRONOUS_IO_NONALERT
    )
    assert windows_create_layout_errors(parsed.to_bytes()) == []


def test_named_create_name_is_utf16_at_offset_120():
    name = "notes.txt"
    encoded = name.encode("utf-16-le")
    body = _create_like_connection(
        name,
        create_options=CreateOptions.FILE_NON_DIRECTORY_FILE,
    ).to_bytes()
    name_offset, name_length, _, _ = create_name_fields(body)

    assert windows_create_layout_errors(body) == []
    assert name_offset == 120
    assert name_length == len(encoded)
    assert name_length % 2 == 0
    assert smb2_relative_range(body, name_offset, name_length) == encoded
    assert body[name_offset - 64 : name_offset - 64 + name_length] == encoded
    assert _message(SMB2Command.CREATE, body).command.Name == name


def test_unaligned_create_name_pads_contexts_to_8_bytes():
    request = _create_like_connection(
        "abc",
        create_options=CreateOptions.FILE_NON_DIRECTORY_FILE,
        create_contexts=[CREATE_CONTEXT("Unkn", b"opaque")],
    )
    body = request.to_bytes()
    name_offset, name_length, ctx_offset, ctx_length = create_name_fields(body)

    assert name_offset == 120
    assert name_length == 6
    assert ctx_offset % 8 == 0
    assert ctx_offset == 128
    assert ctx_length > 0
    assert smb2_relative_range(body, ctx_offset, ctx_length) is not None
    parsed = CREATE_REQ.from_bytes(body)
    assert parsed.Name == "abc"
    assert parsed.CreateContext[0].Name == b"Unkn"
    assert parsed.CreateContext[0].Data == b"opaque"


def test_empty_name_with_create_context_does_not_claim_context_bytes():
    request = _create_like_connection(
        "",
        create_contexts=[CREATE_TIMEWARP_TOKEN(b"\x11" * 8)],
    )
    body = request.to_bytes()
    name_offset, name_length, ctx_offset, ctx_length = create_name_fields(body)

    assert name_length == 0
    assert name_offset == 0
    assert ctx_offset == 120
    assert ctx_offset % 8 == 0
    assert ctx_length > 0
    parsed = CREATE_REQ.from_bytes(body)
    assert parsed.Name is None
    assert isinstance(parsed.CreateContext[0], CREATE_TIMEWARP_TOKEN)


def test_create_parser_rejects_name_offset_inside_header():
    body = bytearray(_create_like_connection("x").to_bytes())
    body[44:46] = struct.pack("<H", 32)
    body[46:48] = struct.pack("<H", 2)

    with pytest.raises(ValueError, match="header"):
        CREATE_REQ.from_bytes(bytes(body))


def test_create_parser_rejects_truncated_name():
    body = bytearray(_create_like_connection("abcd").to_bytes())
    body[46:48] = struct.pack("<H", 80)

    with pytest.raises(ValueError, match="Truncated"):
        CREATE_REQ.from_bytes(bytes(body))


def test_create_parser_still_accepts_spec_empty_name_offset_zero():
    body = bytearray(_create_like_connection("").to_bytes())
    body[44:46] = struct.pack("<H", 0)
    parsed = CREATE_REQ.from_bytes(bytes(body))

    assert parsed.NameLength == 0
    assert parsed.Name is None


def test_create_intflag_combinations_encode_as_or_not_first_member():
    access = (
        FileAccessMask.FILE_READ_DATA
        | FileAccessMask.FILE_READ_ATTRIBUTES
        | FileAccessMask.SYNCHRONIZE
    )
    options = (
        CreateOptions.FILE_DIRECTORY_FILE
        | CreateOptions.FILE_SYNCHRONOUS_IO_NONALERT
    )
    share = (
        ShareAccess.FILE_SHARE_READ
        | ShareAccess.FILE_SHARE_WRITE
        | ShareAccess.FILE_SHARE_DELETE
    )
    body = _create_like_connection(
        "",
        desired_access=access,
        share_mode=share,
        create_options=options,
        file_attrs=FileAttributes(0),
    ).to_bytes()

    assert body[24:28] == struct.pack("<I", access.value)
    assert body[32:36] == struct.pack("<I", share.value)
    assert body[40:44] == struct.pack("<I", options.value)
    assert access.value != FileAccessMask.FILE_READ_DATA.value
    assert options.value == 0x21


def test_generic_read_keeps_high_bit():
    body = _create_like_connection(
        "x",
        desired_access=FileAccessMask.GENERIC_READ,
        create_options=CreateOptions.FILE_NON_DIRECTORY_FILE,
    ).to_bytes()

    assert body[24:28] == struct.pack("<I", 0x80000000)


def test_create_reply_fixed_size_and_context_offset():
    reply = CREATE_REPLY()
    reply.OplockLevel = OplockLevel.SMB2_OPLOCK_LEVEL_NONE
    reply.Flags = CreateReplyFlag.NONE
    reply.CreateAction = CreateAction.FILE_OPENED
    reply.CreationTime = 1
    reply.LastAccessTime = 2
    reply.LastWriteTime = 3
    reply.ChangeTime = 4
    reply.AllocationSize = 4096
    reply.EndofFile = 0
    reply.FileAttributes = FileAttributes.FILE_ATTRIBUTE_DIRECTORY
    reply.FileId = 0x00112233445566778899AABBCCDDEEFF
    empty = reply.to_bytes()

    reply.CreateContext = [CREATE_CONTEXT("MxAc", b"\x00" * 8)]
    with_ctx = reply.to_bytes()
    ctx_offset = int.from_bytes(with_ctx[80:84], "little")
    ctx_length = int.from_bytes(with_ctx[84:88], "little")

    assert len(empty) == 88
    assert ctx_offset == 152
    assert ctx_offset % 8 == 0
    assert smb2_relative_range(with_ctx, ctx_offset, ctx_length) is not None
    parsed = _message(SMB2Command.CREATE, with_ctx, reply=True).command
    assert parsed.CreateContext[0].Name == b"MxAc"


def test_tree_connect_path_is_utf16_at_offset_72():
    path = r"\\192.168.56.10\NETLOGON"
    encoded = path.encode("utf-16-le")
    request = TREE_CONNECT_REQ()
    request.Flags = 0
    request.Path = path
    body = request.to_bytes()
    path_offset = int.from_bytes(body[4:6], "little")
    path_length = int.from_bytes(body[6:8], "little")

    assert int.from_bytes(body[0:2], "little") == 9
    assert path_offset == 72
    assert path_length == len(encoded)
    assert path_length % 2 == 0
    assert body[8:8 + path_length] == encoded
    assert _message(SMB2Command.TREE_CONNECT, body).command.Path == path


def test_tree_connect_flags_zero_is_two_reserved_bytes():
    request = TREE_CONNECT_REQ()
    request.Flags = 0
    request.Path = r"\\server\share"
    body = request.to_bytes()

    assert body[2:4] == b"\x00\x00"
    request.Flags = TreeConnectFlag(0)
    assert request.to_bytes()[2:4] == b"\x00\x00"


def test_session_setup_security_buffer_is_at_offset_88():
    token = b"spnego-token"
    request = SESSION_SETUP_REQ()
    request.Flags = SessionSetupFlag(0)
    request.SecurityMode = NegotiateSecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED
    request.Capabilities = SessionSetupCapabilities.SMB2_GLOBAL_CAP_DFS
    request.Channel = 0
    request.PreviousSessionId = 0
    request.Buffer = token
    body = request.to_bytes()
    offset = int.from_bytes(body[12:14], "little")
    length = int.from_bytes(body[14:16], "little")

    assert int.from_bytes(body[0:2], "little") == 25
    assert offset == 88
    assert length == len(token)
    assert body[24:24 + length] == token
    assert _message(SMB2Command.SESSION_SETUP, body).command.Buffer == token


def test_query_directory_star_pattern_is_utf16_at_offset_96():
    request = QUERY_DIRECTORY_REQ()
    request.FileInformationClass = FileInfoClass.FileFullDirectoryInformation
    request.Flags = 0
    request.FileIndex = 0
    request.FileId = 0xFFEEDDCCBBAA99887766554433221100
    request.FileName = "*"
    request.OutputBufferLength = 65535
    body = request.to_bytes()
    name_offset = int.from_bytes(body[24:26], "little")
    name_length = int.from_bytes(body[26:28], "little")

    assert int.from_bytes(body[0:2], "little") == 33
    assert name_offset == 96
    assert name_length == 2
    assert body[32:34] == "*".encode("utf-16-le")
    parsed = _message(SMB2Command.QUERY_DIRECTORY, body).command
    assert parsed.FileName == "*"


def test_query_info_input_buffer_length_is_four_bytes():
    payload = b"ea-query"
    request = QUERY_INFO_REQ()
    request.InfoType = QueryInfoType.FILE
    request.FileInfoClass = FileInfoClass.FileFullEaInformation
    request.OutputBufferLength = 4096
    request.AdditionalInformation = SecurityInfo(0)
    request.Flags = EaInformation(0)
    request.FileId = 1
    request.Data = payload
    body = request.to_bytes()
    input_offset = int.from_bytes(body[8:10], "little")
    input_length = int.from_bytes(body[12:16], "little")

    assert int.from_bytes(body[0:2], "little") == 41
    assert input_offset == 104
    assert input_length == len(payload)
    assert body[40:40 + input_length] == payload
    parsed = _message(SMB2Command.QUERY_INFO, body).command
    assert parsed.InputBufferLength == len(payload)
    assert parsed.Buffer == payload


def test_read_request_keeps_structure_size_49_trailing_byte():
    request = READ_REQ()
    request.Flags = ReadFlag(0)
    request.Length = 4096
    request.Offset = 0
    request.FileId = 1
    request.MinimumCount = 0
    request.Channel = Channel.SMB2_CHANNEL_NONE
    request.RemainingBytes = 0
    body = request.to_bytes()

    assert int.from_bytes(body[0:2], "little") == 49
    assert len(body) == 49
    assert body[-1:] == b"\x00"
    assert _message(SMB2Command.READ, body).command.Length == 4096


def test_write_request_data_is_at_offset_112():
    data = b"payload-bytes"
    request = WRITE_REQ()
    request.Offset = 8
    request.FileId = 2
    request.Channel = Channel.SMB2_CHANNEL_NONE
    request.Flags = WriteFlag.NONE
    request.Data = data
    body = request.to_bytes()
    data_offset = int.from_bytes(body[2:4], "little")
    length = int.from_bytes(body[4:8], "little")

    assert int.from_bytes(body[0:2], "little") == 49
    assert data_offset == 112
    assert length == len(data)
    assert body[48:48 + length] == data
    assert _message(SMB2Command.WRITE, body).command.Data == data


def test_ioctl_input_is_at_offset_120():
    payload = b"validate-negotiate"
    request = IOCTL_REQ()
    request.CtlCode = CtlCode.FSCTL_VALIDATE_NEGOTIATE_INFO
    request.FileId = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    request.Flags = IOCTLREQFlags.IS_FSCTL
    request.Buffer = payload
    body = request.to_bytes()
    input_offset = int.from_bytes(body[24:28], "little")
    input_count = int.from_bytes(body[28:32], "little")

    assert input_offset == 120
    assert input_count == len(payload)
    assert body[56:56 + input_count] == payload


def test_set_info_buffer_is_at_offset_96():
    payload = b"\x01\x00\x00\x00"
    request = SET_INFO_REQ()
    request.InfoType = QueryInfoType.FILE
    request.FileInfoClass = FileInfoClass.FileDispositionInformation
    request.FileId = 3
    request.Data = payload
    body = request.to_bytes()
    buffer_offset = int.from_bytes(body[8:10], "little")
    buffer_length = int.from_bytes(body[4:8], "little")

    assert int.from_bytes(body[0:2], "little") == 33
    assert buffer_offset == 96
    assert buffer_length == len(payload)
    assert body[32:32 + buffer_length] == payload
    parsed = _message(SMB2Command.SET_INFO, body).command
    assert parsed.BufferLength == len(payload)


def test_close_request_file_id_is_16_little_endian_bytes():
    file_id = 0x00112233445566778899AABBCCDDEEFF
    request = CLOSE_REQ()
    request.Flags = CloseFlag.NONE
    request.FileId = file_id
    body = request.to_bytes()

    assert int.from_bytes(body[0:2], "little") == 24
    assert body[8:24] == file_id.to_bytes(16, "little")
    assert _message(SMB2Command.CLOSE, body).command.FileId == file_id


def test_backslash_create_name_is_not_treated_as_share_root():
    body = _create_like_connection("\\").to_bytes()
    name_offset, name_length, _, _ = create_name_fields(body)

    assert name_offset == 120
    assert name_length == 2
    assert smb2_relative_range(body, name_offset, name_length) == "\\".encode(
        "utf-16-le"
    )
    assert windows_create_layout_errors(body) == []


def test_non_ascii_create_name_stays_even_length_utf16():
    name = "café"
    body = _create_like_connection(
        name,
        create_options=CreateOptions.FILE_NON_DIRECTORY_FILE,
    ).to_bytes()
    encoded = name.encode("utf-16-le")
    name_offset, name_length, _, _ = create_name_fields(body)

    assert name_length == len(encoded) == 8
    assert name_length % 2 == 0
    assert smb2_relative_range(body, name_offset, name_length) == encoded
    assert _message(SMB2Command.CREATE, body).command.Name == name


def test_ioctl_peek_does_not_claim_a_phantom_input_buffer():
    request = IOCTL_REQ()
    request.CtlCode = CtlCode.FSCTL_PIPE_PEEK
    request.FileId = 1
    request.Flags = IOCTLREQFlags.IS_FSCTL
    request.Buffer = None
    body = request.to_bytes()
    input_offset = int.from_bytes(body[24:28], "little")
    input_count = int.from_bytes(body[28:32], "little")

    assert input_offset == 0
    assert input_count == 0
    assert len(body) == 56


def test_query_info_without_input_keeps_zero_buffer_fields():
    request = QUERY_INFO_REQ()
    request.InfoType = QueryInfoType.FILE
    request.FileInfoClass = FileInfoClass.FileAccessInformation
    request.OutputBufferLength = 4096
    request.AdditionalInformation = 0
    request.Flags = 0
    request.FileId = 0
    body = request.to_bytes()

    assert len(body) == 40
    assert int.from_bytes(body[8:10], "little") == 0
    assert int.from_bytes(body[12:16], "little") == 0


def test_write_empty_payload_keeps_data_offset_and_zero_length():
    request = WRITE_REQ()
    request.Offset = 0
    request.FileId = 4
    request.Channel = Channel.SMB2_CHANNEL_NONE
    request.Flags = WriteFlag.NONE
    request.Data = b""
    body = request.to_bytes()

    assert int.from_bytes(body[2:4], "little") == 112
    assert int.from_bytes(body[4:8], "little") == 0
    assert _message(SMB2Command.WRITE, body).command.Data == b""


def test_support_wire_helpers_do_not_import_production_encoders():
    import tests.support.smb_wire as wire

    source = Path(wire.__file__).read_text(encoding="utf-8")
    assert "import aiosmb" not in source
    assert "from aiosmb" not in source


def test_message_round_trip_preserves_create_and_tree_connect_bodies():
    create_body = _create_like_connection("").to_bytes()
    tree = TREE_CONNECT_REQ()
    tree.Flags = 0
    tree.Path = r"\\host\share"
    tree_body = tree.to_bytes()

    create_message = _message(SMB2Command.CREATE, create_body)
    tree_message = _message(SMB2Command.TREE_CONNECT, tree_body)

    assert command_body_from_smb2_message(create_message.to_bytes()) == create_body
    assert command_body_from_smb2_message(tree_message.to_bytes()) == tree_body
    assert windows_create_layout_errors(
        command_body_from_smb2_message(create_message.to_bytes())
    ) == []
