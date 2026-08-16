import io

from aiosmb.wintypes.fscc.FileAttributes import FileAttributes
from aiosmb.wintypes.fscc.structures._helpers import (
	as_int,
	filetime_value,
	read_exact,
)


class FileNetworkOpenInformation:
	def __init__(self):
		self.CreationTime = 0
		self.LastAccessTime = 0
		self.LastWriteTime = 0
		self.ChangeTime = 0
		self.AllocationSize = 0
		self.EndOfFile = 0
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
		t += self.AllocationSize.to_bytes(8, 'little', signed=True)
		t += self.EndOfFile.to_bytes(8, 'little', signed=True)
		t += as_int(self.FileAttributes).to_bytes(4, 'little')
		t += self.Reserved.to_bytes(4, 'little')
		return t

	@staticmethod
	def from_bytes(data):
		return FileNetworkOpenInformation.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		data = read_exact(buff, 56, 'FILE_NETWORK_OPEN_INFORMATION')
		msg = FileNetworkOpenInformation()
		msg.CreationTime = int.from_bytes(data[0:8], 'little', signed=True)
		msg.LastAccessTime = int.from_bytes(data[8:16], 'little', signed=True)
		msg.LastWriteTime = int.from_bytes(data[16:24], 'little', signed=True)
		msg.ChangeTime = int.from_bytes(data[24:32], 'little', signed=True)
		msg.AllocationSize = int.from_bytes(data[32:40], 'little', signed=True)
		msg.EndOfFile = int.from_bytes(data[40:48], 'little', signed=True)
		msg.FileAttributes = FileAttributes(
			int.from_bytes(data[48:52], 'little')
		)
		msg.Reserved = int.from_bytes(data[52:56], 'little')
		return msg
