import io

from aiosmb.wintypes.fscc.structures._helpers import read_exact


class FileFsSizeInformation:
	def __init__(self):
		self.TotalAllocationUnits = 0
		self.AvailableAllocationUnits = 0
		self.SectorsPerAllocationUnit = 0
		self.BytesPerSector = 0

	def to_bytes(self):
		t  = self.TotalAllocationUnits.to_bytes(8, 'little', signed=True)
		t += self.AvailableAllocationUnits.to_bytes(8, 'little', signed=True)
		t += self.SectorsPerAllocationUnit.to_bytes(4, 'little')
		t += self.BytesPerSector.to_bytes(4, 'little')
		return t

	@staticmethod
	def from_bytes(data):
		return FileFsSizeInformation.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		data = read_exact(buff, 24, 'FILE_FS_SIZE_INFORMATION')
		msg = FileFsSizeInformation()
		msg.TotalAllocationUnits = int.from_bytes(
			data[0:8], 'little', signed=True
		)
		msg.AvailableAllocationUnits = int.from_bytes(
			data[8:16], 'little', signed=True
		)
		msg.SectorsPerAllocationUnit = int.from_bytes(data[16:20], 'little')
		msg.BytesPerSector = int.from_bytes(data[20:24], 'little')
		return msg
