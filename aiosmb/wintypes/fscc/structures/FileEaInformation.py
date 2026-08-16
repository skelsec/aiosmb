import io

from aiosmb.wintypes.fscc.structures._helpers import read_exact


class FileEaInformation:
	def __init__(self):
		self.EaSize = 0

	def to_bytes(self):
		return self.EaSize.to_bytes(4, 'little', signed=False)

	@staticmethod
	def from_bytes(data):
		return FileEaInformation.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		msg = FileEaInformation()
		msg.EaSize = int.from_bytes(
			read_exact(buff, 4, 'FILE_EA_INFORMATION'), 'little'
		)
		return msg
