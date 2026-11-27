import enum
import io

from aiosmb.protocol.smb2.commands.query_info import QueryInfoType
from aiosmb.wintypes.fscc.structures.fileinfoclass import (
	FileInfoClass,
	FileSystemInfoClass,
)


SMB2_HEADER_SIZE = 64
SET_INFO_REQUEST_FIXED_SIZE = 32
SetInfoType = QueryInfoType


def _int_value(value):
	if isinstance(value, enum.Enum):
		return value.value
	return value


def _decode_set_info_data(info_type, info_class, data):
	if info_type != QueryInfoType.FILE:
		return data

	from aiosmb.wintypes.fscc.structures.FileBasicInformation import (
		FileBasicInformation,
	)
	from aiosmb.wintypes.fscc.structures.FileDispositionInformation import (
		FileDispositionInformation,
	)
	from aiosmb.wintypes.fscc.structures.FileEndOfFileInformation import (
		FileEndOfFileInformation,
	)
	from aiosmb.wintypes.fscc.structures.FileRenameInformation import (
		FileRenameInformation,
	)

	decoders = {
		FileInfoClass.FileBasicInformation: FileBasicInformation,
		FileInfoClass.FileDispositionInformation: FileDispositionInformation,
		FileInfoClass.FileEndOfFileInformation: FileEndOfFileInformation,
		FileInfoClass.FileRenameInformation: FileRenameInformation,
	}
	decoder = decoders.get(info_class)
	return decoder.from_bytes(data) if decoder is not None else data


class SET_INFO_REQ:
	def __init__(self):
		self.StructureSize = 33
		self.InfoType = None
		self.FileInfoClass = None
		self.BufferLength = 0
		self.BufferOffset = 0
		self.Reserved = 0
		self.AdditionalInformation = 0
		self.FileId = None
		self.Buffer = b''

		# High-level value. It can be bytes-like or an FSCC object exposing
		# to_bytes(). Parsed supported FILE classes are returned as FSCC objects.
		self.Data = None

	def to_bytes(self):
		data = self.Data if self.Data is not None else self.Buffer
		if hasattr(data, 'to_bytes') and not isinstance(
			data, (bytes, bytearray, memoryview)
		):
			data = data.to_bytes()
		if data is None:
			data = b''
		if not isinstance(data, (bytes, bytearray, memoryview)):
			raise TypeError('SET_INFO data must be bytes-like or serializable')
		data = bytes(data)

		self.Buffer = data
		self.BufferLength = len(data)
		self.BufferOffset = (
			SMB2_HEADER_SIZE + SET_INFO_REQUEST_FIXED_SIZE if data else 0
		)

		t  = self.StructureSize.to_bytes(2, byteorder='little', signed=False)
		t += _int_value(self.InfoType).to_bytes(
			1, byteorder='little', signed=False
		)
		t += _int_value(self.FileInfoClass).to_bytes(
			1, byteorder='little', signed=False
		)
		t += self.BufferLength.to_bytes(4, byteorder='little', signed=False)
		t += self.BufferOffset.to_bytes(2, byteorder='little', signed=False)
		t += self.Reserved.to_bytes(2, byteorder='little', signed=False)
		t += _int_value(self.AdditionalInformation).to_bytes(
			4, byteorder='little', signed=False
		)
		t += self.FileId.to_bytes(16, byteorder='little', signed=False)
		t += data if data else b'\x00'
		return t

	@staticmethod
	def from_bytes(data):
		return SET_INFO_REQ.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		msg = SET_INFO_REQ()
		command_start = buff.tell()
		fixed = buff.read(SET_INFO_REQUEST_FIXED_SIZE)
		if len(fixed) != SET_INFO_REQUEST_FIXED_SIZE:
			raise ValueError('Truncated SMB2 SET_INFO request')

		msg.StructureSize = int.from_bytes(fixed[0:2], byteorder='little')
		if msg.StructureSize != 33:
			raise ValueError('Invalid SMB2 SET_INFO request StructureSize')
		msg.InfoType = QueryInfoType(fixed[2])
		info_class = fixed[3]
		if msg.InfoType == QueryInfoType.FILE:
			msg.FileInfoClass = FileInfoClass(info_class)
		elif msg.InfoType == QueryInfoType.FILESYSTEM:
			msg.FileInfoClass = FileSystemInfoClass(info_class)
		else:
			msg.FileInfoClass = info_class
		msg.BufferLength = int.from_bytes(fixed[4:8], byteorder='little')
		msg.BufferOffset = int.from_bytes(fixed[8:10], byteorder='little')
		msg.Reserved = int.from_bytes(fixed[10:12], byteorder='little')
		msg.AdditionalInformation = int.from_bytes(
			fixed[12:16], byteorder='little'
		)
		msg.FileId = int.from_bytes(fixed[16:32], byteorder='little')

		if msg.BufferLength:
			if msg.BufferOffset < SMB2_HEADER_SIZE + SET_INFO_REQUEST_FIXED_SIZE:
				raise ValueError('Invalid SMB2 SET_INFO BufferOffset')
			position = command_start - SMB2_HEADER_SIZE + msg.BufferOffset
			buff.seek(position, io.SEEK_SET)
			msg.Buffer = buff.read(msg.BufferLength)
			if len(msg.Buffer) != msg.BufferLength:
				raise ValueError('Truncated SMB2 SET_INFO data')
			msg.Data = _decode_set_info_data(
				msg.InfoType, msg.FileInfoClass, msg.Buffer
			)
		else:
			msg.Buffer = b''
			msg.Data = b''
		return msg

	def __repr__(self):
		return (
			'==== SMB2 SET INFO REQ ====\r\n'
			'InfoType: %s\r\n'
			'FileInfoClass: %s\r\n'
			'BufferLength: %s\r\n'
			'FileId: %s\r\n'
			'Data: %s\r\n'
		) % (
			self.InfoType,
			self.FileInfoClass,
			self.BufferLength,
			self.FileId,
			self.Data,
		)


class SET_INFO_REPLY:
	def __init__(self):
		self.StructureSize = 2

	def to_bytes(self):
		return self.StructureSize.to_bytes(
			2, byteorder='little', signed=False
		)

	@staticmethod
	def from_bytes(data):
		return SET_INFO_REPLY.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		msg = SET_INFO_REPLY()
		data = buff.read(2)
		if len(data) != 2:
			raise ValueError('Truncated SMB2 SET_INFO response')
		msg.StructureSize = int.from_bytes(data, byteorder='little')
		if msg.StructureSize != 2:
			raise ValueError('Invalid SMB2 SET_INFO response StructureSize')
		return msg

	def __repr__(self):
		return '==== SMB2 SET INFO REPLY ====\r\nStructureSize: %s\r\n' % (
			self.StructureSize,
		)
