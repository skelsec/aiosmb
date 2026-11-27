import io

from aiosmb.wintypes.fscc.structures._helpers import (
	decode_utf16,
	encode_utf16,
	read_exact,
)


class FileRenameInformation:
	def __init__(self):
		self.ReplaceIfExists = False
		self.Reserved = b'\x00' * 7
		self.RootDirectory = 0
		self.FileNameLength = 0
		self.FileName = ''

	def to_bytes(self):
		name = encode_utf16(self.FileName, 'FileName')
		self.FileNameLength = len(name)
		reserved = self.Reserved
		if isinstance(reserved, int):
			reserved = reserved.to_bytes(7, 'little')
		if not isinstance(reserved, (bytes, bytearray, memoryview)):
			raise TypeError('Reserved must be a 7-byte value')
		reserved = bytes(reserved)
		if len(reserved) != 7:
			raise ValueError('Reserved must be exactly 7 bytes')

		t  = int(bool(self.ReplaceIfExists)).to_bytes(1, 'little')
		t += reserved
		t += self.RootDirectory.to_bytes(8, 'little', signed=False)
		t += self.FileNameLength.to_bytes(4, 'little')
		t += name
		return t

	@staticmethod
	def from_bytes(data):
		return FileRenameInformation.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		fixed = read_exact(buff, 20, 'FILE_RENAME_INFORMATION')
		msg = FileRenameInformation()
		msg.ReplaceIfExists = bool(fixed[0])
		msg.Reserved = fixed[1:8]
		msg.RootDirectory = int.from_bytes(fixed[8:16], 'little')
		msg.FileNameLength = int.from_bytes(fixed[16:20], 'little')
		name = read_exact(
			buff, msg.FileNameLength, 'FILE_RENAME_INFORMATION FileName'
		)
		msg.FileName = decode_utf16(name, 'FileName')
		return msg
