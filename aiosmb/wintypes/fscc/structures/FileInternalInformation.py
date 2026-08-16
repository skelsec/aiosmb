import io

from aiosmb.wintypes.fscc.structures._helpers import read_exact


class FileInternalInformation:
	def __init__(self):
		self.IndexNumber = 0

	def to_bytes(self):
		return self.IndexNumber.to_bytes(8, 'little', signed=True)

	@staticmethod
	def from_bytes(data):
		return FileInternalInformation.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		msg = FileInternalInformation()
		msg.IndexNumber = int.from_bytes(
			read_exact(buff, 8, 'FILE_INTERNAL_INFORMATION'),
			'little',
			signed=True,
		)
		return msg
