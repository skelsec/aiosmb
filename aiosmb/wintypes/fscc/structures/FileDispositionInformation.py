import io

from aiosmb.wintypes.fscc.structures._helpers import read_exact


class FileDispositionInformation:
	def __init__(self):
		self.DeletePending = False

	@property
	def DeleteFile(self):
		return self.DeletePending

	@DeleteFile.setter
	def DeleteFile(self, value):
		self.DeletePending = bool(value)

	def to_bytes(self):
		return int(bool(self.DeletePending)).to_bytes(1, 'little')

	@staticmethod
	def from_bytes(data):
		return FileDispositionInformation.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		msg = FileDispositionInformation()
		msg.DeletePending = bool(
			read_exact(buff, 1, 'FILE_DISPOSITION_INFORMATION')[0]
		)
		return msg
