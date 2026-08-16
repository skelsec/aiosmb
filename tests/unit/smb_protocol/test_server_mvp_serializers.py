"""Golden SMB 2.0.2 server serializer vectors."""

import struct

import pytest

from aiosmb.protocol.smb2.command_codes import SMB2Command
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
from aiosmb.protocol.smb2.commands.query_info import QueryInfoType
from aiosmb.protocol.smb2.commands.read import READ_REPLY
from aiosmb.protocol.smb2.commands.set_info import SET_INFO_REPLY, SET_INFO_REQ
from aiosmb.protocol.smb2.commands.write import WRITE_REPLY
from aiosmb.protocol.smb2.headers.common import SMB2HeaderFlag
from aiosmb.protocol.smb2.message import SMB2Message
from aiosmb.wintypes.access_mask import FileAccessMask
from aiosmb.wintypes.fscc.FileAttributes import FileAttributes
from aiosmb.wintypes.fscc.structures.FileEndOfFileInformation import (
	FileEndOfFileInformation,
)
from aiosmb.wintypes.fscc.structures.fileinfoclass import FileInfoClass


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


def test_read_reply_serializes_spec_offsets_and_lengths():
	reply = READ_REPLY()
	reply.DataRemaining = 9
	reply.Buffer = b"payload"

	wire = reply.to_bytes()

	assert wire == struct.pack("<HBBIII", 17, 80, 0, 7, 9, 0) + b"payload"
	assert READ_REPLY.from_bytes(wire).Buffer == b"payload"

	empty = READ_REPLY()
	assert empty.to_bytes() == struct.pack("<HBBIII", 17, 0, 0, 0, 0, 0)


def test_write_reply_serializes_fixed_smb202_layout():
	reply = WRITE_REPLY()
	reply.Count = 0x10203040
	reply.Remaining = 3

	assert reply.to_bytes() == struct.pack(
		"<HHIIHH", 17, 0, 0x10203040, 3, 0, 0
	)


def test_set_info_typed_payload_golden_and_dispatch():
	eof = FileEndOfFileInformation()
	eof.EndOfFile = 0x102030405060708
	request = SET_INFO_REQ()
	request.InfoType = QueryInfoType.FILE
	request.FileInfoClass = FileInfoClass.FileEndOfFileInformation
	request.FileId = 0x00112233445566778899AABBCCDDEEFF
	request.Data = eof

	body = request.to_bytes()
	golden = struct.pack(
		"<HBBIHHI16s",
		33,
		QueryInfoType.FILE.value,
		FileInfoClass.FileEndOfFileInformation.value,
		8,
		96,
		0,
		0,
		request.FileId.to_bytes(16, "little"),
	) + eof.to_bytes()
	message = SMB2Message.from_bytes(_header(SMB2Command.SET_INFO) + body)

	assert body == golden
	assert isinstance(message.command, SET_INFO_REQ)
	assert isinstance(message.command.Data, FileEndOfFileInformation)
	assert message.command.Data.EndOfFile == eof.EndOfFile

	reply_body = SET_INFO_REPLY().to_bytes()
	reply_message = SMB2Message.from_bytes(
		_header(SMB2Command.SET_INFO, reply=True) + reply_body
	)
	assert reply_body == b"\x02\x00"
	assert isinstance(reply_message.command, SET_INFO_REPLY)


def _create_request():
	request = CREATE_REQ()
	request.RequestedOplockLevel = OplockLevel.SMB2_OPLOCK_LEVEL_NONE
	request.ImpersonationLevel = ImpersonationLevel.Impersonation
	request.DesiredAccess = FileAccessMask.GENERIC_READ
	request.FileAttributes = FileAttributes(0)
	request.ShareAccess = ShareAccess.FILE_SHARE_READ
	request.CreateDisposition = CreateDisposition.FILE_OPEN
	request.CreateOptions = CreateOptions.FILE_NON_DIRECTORY_FILE
	request.Name = "x"
	request.CreateContext = [
		CREATE_CONTEXT("Unkn", b"opaque"),
		CREATE_TIMEWARP_TOKEN(b"\x11" * 8),
	]
	return request


def test_create_request_parses_unknown_context_records():
	body = _create_request().to_bytes()
	parsed = CREATE_REQ.from_bytes(body)

	assert parsed.CreateContextsOffset == 128
	assert parsed.CreateContextsOffset % 8 == 0
	assert len(parsed.CreateContext) == 2
	assert type(parsed.CreateContext[0]) is CREATE_CONTEXT
	assert parsed.CreateContext[0].Name == b"Unkn"
	assert parsed.CreateContext[0].Data == b"opaque"
	assert isinstance(parsed.CreateContext[1], CREATE_TIMEWARP_TOKEN)
	assert parsed.CreateContext[1].Data == b"\x11" * 8
	assert int.from_bytes(parsed.CreateContext[0].Raw[0:4], "little") == 32


def test_empty_create_context_uses_zero_data_offset():
	context = CREATE_CONTEXT("Unkn", b"")

	wire = context.to_bytes()
	parsed = CREATE_CONTEXT.from_bytes(wire)

	assert int.from_bytes(wire[10:12], "little") == 0
	assert parsed.DataOffset == 0
	assert parsed.Data == b""


def test_create_reply_context_chain_has_relative_offsets_and_round_trips():
	reply = CREATE_REPLY()
	reply.OplockLevel = OplockLevel.SMB2_OPLOCK_LEVEL_NONE
	reply.Flags = CreateReplyFlag.NONE
	reply.CreateAction = CreateAction.FILE_OPENED
	reply.CreationTime = 1
	reply.LastAccessTime = 2
	reply.LastWriteTime = 3
	reply.ChangeTime = 4
	reply.AllocationSize = 4096
	reply.EndofFile = 5
	reply.FileAttributes = FileAttributes.FILE_ATTRIBUTE_ARCHIVE
	reply.FileId = 9
	reply.CreateContext = [
		CREATE_CONTEXT("Unkn", b"opaque"),
		CREATE_CONTEXT("MxAc", b"\x00" * 8),
	]

	body = reply.to_bytes()
	context_offset = int.from_bytes(body[80:84], "little")
	context_length = int.from_bytes(body[84:88], "little")
	contexts = body[context_offset - 64:context_offset - 64 + context_length]
	parsed = CREATE_REPLY.from_bytes(body)

	assert context_offset == 152
	assert context_length == 64
	assert int.from_bytes(contexts[0:4], "little") == 32
	assert int.from_bytes(contexts[32:36], "little") == 0
	assert [context.Name for context in parsed.CreateContext] == [
		b"Unkn",
		b"MxAc",
	]
	assert parsed.to_bytes() == body
