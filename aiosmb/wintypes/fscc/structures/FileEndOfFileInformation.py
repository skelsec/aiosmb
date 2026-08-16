import io

from aiosmb.wintypes.fscc.structures._helpers import read_exact


class FileEndOfFileInformation:
	def __init__(self):
		self.EndOfFile = 0

	def to_bytes(self):
		return self.EndOfFile.to_bytes(8, 'little', signed=True)

	@staticmethod
	def from_bytes(data):
		return FileEndOfFileInformation.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		msg = FileEndOfFileInformation()
		msg.EndOfFile = int.from_bytes(
			read_exact(buff, 8, 'FILE_END_OF_FILE_INFORMATION'),
			'little',
			signed=True,
		)
		return msg
