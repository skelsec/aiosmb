import io

from aiosmb.wintypes.fscc.structures._helpers import read_exact


class FileFsFullSizeInformation:
	def __init__(self):
		self.TotalAllocationUnits = 0
		self.CallerAvailableAllocationUnits = 0
		self.ActualAvailableAllocationUnits = 0
		self.SectorsPerAllocationUnit = 0
		self.BytesPerSector = 0

	def to_bytes(self):
		t  = self.TotalAllocationUnits.to_bytes(8, 'little', signed=True)
		t += self.CallerAvailableAllocationUnits.to_bytes(
			8, 'little', signed=True
		)
		t += self.ActualAvailableAllocationUnits.to_bytes(
			8, 'little', signed=True
		)
		t += self.SectorsPerAllocationUnit.to_bytes(4, 'little')
		t += self.BytesPerSector.to_bytes(4, 'little')
		return t

	@staticmethod
	def from_bytes(data):
		return FileFsFullSizeInformation.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		data = read_exact(buff, 32, 'FILE_FS_FULL_SIZE_INFORMATION')
		msg = FileFsFullSizeInformation()
		msg.TotalAllocationUnits = int.from_bytes(
			data[0:8], 'little', signed=True
		)
		msg.CallerAvailableAllocationUnits = int.from_bytes(
			data[8:16], 'little', signed=True
		)
		msg.ActualAvailableAllocationUnits = int.from_bytes(
			data[16:24], 'little', signed=True
		)
		msg.SectorsPerAllocationUnit = int.from_bytes(data[24:28], 'little')
		msg.BytesPerSector = int.from_bytes(data[28:32], 'little')
		return msg
