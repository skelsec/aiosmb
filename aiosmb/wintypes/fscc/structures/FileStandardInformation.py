import io

from aiosmb.wintypes.fscc.structures._helpers import read_exact


class FileStandardInformation:
	def __init__(self):
		self.AllocationSize = 0
		self.EndOfFile = 0
		self.NumberOfLinks = 0
		self.DeletePending = False
		self.Directory = False
		self.Reserved = 0

	def to_bytes(self):
		t  = self.AllocationSize.to_bytes(8, 'little', signed=True)
		t += self.EndOfFile.to_bytes(8, 'little', signed=True)
		t += self.NumberOfLinks.to_bytes(4, 'little', signed=False)
		t += int(bool(self.DeletePending)).to_bytes(1, 'little')
		t += int(bool(self.Directory)).to_bytes(1, 'little')
		t += self.Reserved.to_bytes(2, 'little', signed=False)
		return t

	@staticmethod
	def from_bytes(data):
		return FileStandardInformation.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		data = read_exact(buff, 24, 'FILE_STANDARD_INFORMATION')
		msg = FileStandardInformation()
		msg.AllocationSize = int.from_bytes(data[0:8], 'little', signed=True)
		msg.EndOfFile = int.from_bytes(data[8:16], 'little', signed=True)
		msg.NumberOfLinks = int.from_bytes(data[16:20], 'little')
		msg.DeletePending = bool(data[20])
		msg.Directory = bool(data[21])
		msg.Reserved = int.from_bytes(data[22:24], 'little')
		return msg
