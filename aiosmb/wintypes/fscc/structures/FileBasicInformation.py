import io

from aiosmb.wintypes.fscc.FileAttributes import FileAttributes
from aiosmb.wintypes.fscc.structures._helpers import (
	as_int,
	filetime_value,
	read_exact,
)


class FileBasicInformation:
	def __init__(self):
		self.CreationTime = 0
		self.LastAccessTime = 0
		self.LastWriteTime = 0
		self.ChangeTime = 0
		self.FileAttributes = FileAttributes(0)
		self.Reserved = 0

	def to_bytes(self):
		t = b''
		for value in (
			self.CreationTime,
			self.LastAccessTime,
			self.LastWriteTime,
			self.ChangeTime,
		):
			t += filetime_value(value).to_bytes(
				8, byteorder='little', signed=True
			)
		t += as_int(self.FileAttributes).to_bytes(
			4, byteorder='little', signed=False
		)
		t += self.Reserved.to_bytes(4, byteorder='little', signed=False)
		return t

	@staticmethod
	def from_bytes(data):
		return FileBasicInformation.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		data = read_exact(buff, 40, 'FILE_BASIC_INFORMATION')
		msg = FileBasicInformation()
		msg.CreationTime = int.from_bytes(data[0:8], 'little', signed=True)
		msg.LastAccessTime = int.from_bytes(data[8:16], 'little', signed=True)
		msg.LastWriteTime = int.from_bytes(data[16:24], 'little', signed=True)
		msg.ChangeTime = int.from_bytes(data[24:32], 'little', signed=True)
		msg.FileAttributes = FileAttributes(
			int.from_bytes(data[32:36], 'little')
		)
		msg.Reserved = int.from_bytes(data[36:40], 'little')
		return msg
