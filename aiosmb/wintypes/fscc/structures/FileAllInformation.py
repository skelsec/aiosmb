import io

from aiosmb.wintypes.fscc.structures.FileBasicInformation import (
	FileBasicInformation,
)
from aiosmb.wintypes.fscc.structures.FileEaInformation import FileEaInformation
from aiosmb.wintypes.fscc.structures.FileInternalInformation import (
	FileInternalInformation,
)
from aiosmb.wintypes.fscc.structures.FileStandardInformation import (
	FileStandardInformation,
)
from aiosmb.wintypes.fscc.structures._helpers import (
	as_int,
	decode_utf16,
	encode_utf16,
	read_exact,
)


class FileAccessInformation:
	def __init__(self):
		self.AccessFlags = 0

	def to_bytes(self):
		return as_int(self.AccessFlags).to_bytes(4, 'little', signed=False)

	@staticmethod
	def from_buffer(buff):
		msg = FileAccessInformation()
		msg.AccessFlags = int.from_bytes(
			read_exact(buff, 4, 'FILE_ACCESS_INFORMATION'), 'little'
		)
		return msg


class FilePositionInformation:
	def __init__(self):
		self.CurrentByteOffset = 0

	def to_bytes(self):
		return self.CurrentByteOffset.to_bytes(8, 'little', signed=True)

	@staticmethod
	def from_buffer(buff):
		msg = FilePositionInformation()
		msg.CurrentByteOffset = int.from_bytes(
			read_exact(buff, 8, 'FILE_POSITION_INFORMATION'),
			'little',
			signed=True,
		)
		return msg


class FileModeInformation:
	def __init__(self):
		self.Mode = 0

	def to_bytes(self):
		return as_int(self.Mode).to_bytes(4, 'little', signed=False)

	@staticmethod
	def from_buffer(buff):
		msg = FileModeInformation()
		msg.Mode = int.from_bytes(
			read_exact(buff, 4, 'FILE_MODE_INFORMATION'), 'little'
		)
		return msg


class FileAlignmentInformation:
	def __init__(self):
		self.AlignmentRequirement = 0

	def to_bytes(self):
		return as_int(self.AlignmentRequirement).to_bytes(
			4, 'little', signed=False
		)

	@staticmethod
	def from_buffer(buff):
		msg = FileAlignmentInformation()
		msg.AlignmentRequirement = int.from_bytes(
			read_exact(buff, 4, 'FILE_ALIGNMENT_INFORMATION'), 'little'
		)
		return msg


class FileNameInformation:
	def __init__(self):
		self.FileNameLength = 0
		self.FileName = ''

	def to_bytes(self):
		name = encode_utf16(self.FileName, 'FileName')
		self.FileNameLength = len(name)
		return self.FileNameLength.to_bytes(4, 'little') + name

	@staticmethod
	def from_buffer(buff):
		msg = FileNameInformation()
		msg.FileNameLength = int.from_bytes(
			read_exact(buff, 4, 'FILE_NAME_INFORMATION'), 'little'
		)
		name = read_exact(
			buff, msg.FileNameLength, 'FILE_NAME_INFORMATION FileName'
		)
		msg.FileName = decode_utf16(name, 'FileName')
		return msg


class FileAllInformation:
	def __init__(self):
		self.BasicInformation = FileBasicInformation()
		self.StandardInformation = FileStandardInformation()
		self.InternalInformation = FileInternalInformation()
		self.EaInformation = FileEaInformation()
		self.AccessInformation = FileAccessInformation()
		self.PositionInformation = FilePositionInformation()
		self.ModeInformation = FileModeInformation()
		self.AlignmentInformation = FileAlignmentInformation()
		self.NameInformation = FileNameInformation()

	def to_bytes(self):
		return b''.join(
			(
				self.BasicInformation.to_bytes(),
				self.StandardInformation.to_bytes(),
				self.InternalInformation.to_bytes(),
				self.EaInformation.to_bytes(),
				self.AccessInformation.to_bytes(),
				self.PositionInformation.to_bytes(),
				self.ModeInformation.to_bytes(),
				self.AlignmentInformation.to_bytes(),
				self.NameInformation.to_bytes(),
			)
		)

	@staticmethod
	def from_bytes(data):
		return FileAllInformation.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		msg = FileAllInformation()
		msg.BasicInformation = FileBasicInformation.from_buffer(buff)
		msg.StandardInformation = FileStandardInformation.from_buffer(buff)
		msg.InternalInformation = FileInternalInformation.from_buffer(buff)
		msg.EaInformation = FileEaInformation.from_buffer(buff)
		msg.AccessInformation = FileAccessInformation.from_buffer(buff)
		msg.PositionInformation = FilePositionInformation.from_buffer(buff)
		msg.ModeInformation = FileModeInformation.from_buffer(buff)
		msg.AlignmentInformation = FileAlignmentInformation.from_buffer(buff)
		msg.NameInformation = FileNameInformation.from_buffer(buff)
		return msg
