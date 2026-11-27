import enum
import io

from aiosmb.protocol.smb2.commands.negotiate import SMB2CompressionType, SMB2CompressionFlags
	
#https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/1d435f21-9a21-4f4c-828e-624a176cf2a0
class SMB2Header_COMPRESSION_TRANSFORM:
	def __init__(self):
		self.ProtocolId = b'\xFCSMB'
		self.OriginalCompressedSegmentSize = None
		self.CompressionAlgorithm = None
		self.Flags = None
		self.Offset = None

	@staticmethod
	def construct(comp_data, algo, original_size, offset = 0, is_chained = False):
		comp_hdr = SMB2Header_COMPRESSION_TRANSFORM()
		comp_hdr.OriginalCompressedSegmentSize = original_size
		comp_hdr.CompressionAlgorithm = algo
		if is_chained is False:
			comp_hdr.Flags = SMB2CompressionFlags.NONE
			comp_hdr.Offset = offset
		else:
			comp_hdr.Flags = SMB2CompressionFlags.CHAINED
			comp_hdr.Offset = offset

		return comp_hdr
		
	def to_bytes(self):
		t = self.ProtocolId
		t += self.OriginalCompressedSegmentSize.to_bytes(4, byteorder='little', signed = False)
		t += self.CompressionAlgorithm.value.to_bytes(2, byteorder='little', signed = False)
		t += self.Flags.value.to_bytes(2, byteorder='little', signed = False)
		t += self.Offset.to_bytes(4, byteorder='little', signed = False)

		return t
		
	@staticmethod
	def from_buffer(buff):
		hdr = SMB2Header_COMPRESSION_TRANSFORM()
		hdr.ProtocolId = buff.read(4)
		if hdr.ProtocolId != b'\xFCSMB':
			raise ValueError('Invalid SMB2 compression transform protocol ID')
		original_size = buff.read(4)
		algorithm = buff.read(2)
		flags = buff.read(2)
		offset = buff.read(4)
		if any(len(field) != size for field, size in (
			(original_size, 4),
			(algorithm, 2),
			(flags, 2),
			(offset, 4),
		)):
			raise ValueError('Truncated SMB2 compression transform header')
		hdr.OriginalCompressedSegmentSize = int.from_bytes(original_size, byteorder='little', signed = False)
		hdr.CompressionAlgorithm = SMB2CompressionType(int.from_bytes(algorithm, byteorder='little', signed = False))
		hdr.Flags = SMB2CompressionFlags(int.from_bytes(flags, byteorder='little', signed = False))
		hdr.Offset = int.from_bytes(offset, byteorder='little', signed = False)
		return hdr

	def validate(self, payload_length, max_output_size, allowed_algorithms, allow_chained = False):
		if self.Flags == SMB2CompressionFlags.CHAINED and allow_chained is False:
			raise ValueError('Chained SMB2 compression is not supported')
		if self.Flags != SMB2CompressionFlags.NONE:
			raise ValueError('Unsupported SMB2 compression transform flags')
		if self.CompressionAlgorithm == SMB2CompressionType.NONE:
			raise ValueError('NONE is not valid for an unchained compression transform')
		if self.CompressionAlgorithm not in allowed_algorithms:
			raise ValueError('SMB2 compression transform used an algorithm that was not negotiated')
		if self.Offset > payload_length:
			raise ValueError('SMB2 compression transform offset exceeds the payload length')
		if self.OriginalCompressedSegmentSize == 0:
			raise ValueError('SMB2 compression transform declares an empty output segment')
		if self.OriginalCompressedSegmentSize > max_output_size:
			raise ValueError('SMB2 compression transform segment exceeds the connection limit')
		total_output_size = self.Offset + self.OriginalCompressedSegmentSize
		if total_output_size > max_output_size:
			raise ValueError('SMB2 compression transform output exceeds the connection limit')
		if self.Offset == payload_length:
			raise ValueError('SMB2 compression transform has no compressed data')
		return total_output_size
