import io

from aiosmb.wintypes.fscc.structures._helpers import (
	decode_utf16,
	encode_utf16,
	filetime_value,
	read_exact,
)


class FileFsVolumeInformation:
	def __init__(self):
		self.VolumeCreationTime = 0
		self.VolumeSerialNumber = 0
		self.VolumeLabelLength = 0
		self.SupportsObjects = False
		self.Reserved = 0
		self.VolumeLabel = ''

	def to_bytes(self):
		label = encode_utf16(self.VolumeLabel, 'VolumeLabel')
		self.VolumeLabelLength = len(label)
		t  = filetime_value(self.VolumeCreationTime).to_bytes(
			8, 'little', signed=True
		)
		t += self.VolumeSerialNumber.to_bytes(4, 'little')
		t += self.VolumeLabelLength.to_bytes(4, 'little')
		t += int(bool(self.SupportsObjects)).to_bytes(1, 'little')
		t += self.Reserved.to_bytes(1, 'little')
		t += label
		return t

	@staticmethod
	def from_bytes(data):
		return FileFsVolumeInformation.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		fixed = read_exact(buff, 18, 'FILE_FS_VOLUME_INFORMATION')
		msg = FileFsVolumeInformation()
		msg.VolumeCreationTime = int.from_bytes(
			fixed[0:8], 'little', signed=True
		)
		msg.VolumeSerialNumber = int.from_bytes(fixed[8:12], 'little')
		msg.VolumeLabelLength = int.from_bytes(fixed[12:16], 'little')
		msg.SupportsObjects = bool(fixed[16])
		msg.Reserved = fixed[17]
		label = read_exact(
			buff,
			msg.VolumeLabelLength,
			'FILE_FS_VOLUME_INFORMATION VolumeLabel',
		)
		msg.VolumeLabel = decode_utf16(label, 'VolumeLabel')
		return msg
