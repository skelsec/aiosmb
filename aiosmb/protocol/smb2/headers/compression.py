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
	def construct(comp_data, algo, original_size, compressed_size, is_chained = False):
		comp_hdr = SMB2Header_COMPRESSION_TRANSFORM()
		comp_hdr.OriginalCompressedSegmentSize = original_size
		comp_hdr.CompressionAlgorithm = algo
		if is_chained is False:
			comp_hdr.Flags = SMB2CompressionFlags.NONE
			comp_hdr.Offset = compressed_size
		else:
			comp_hdr.Flags = SMB2CompressionFlags.CHAINED
			comp_hdr.Offset = compressed_size

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
		assert hdr.ProtocolId == b'\xFCSMB'
		hdr.OriginalCompressedSegmentSize = int.from_bytes(buff.read(4), byteorder='little', signed = False)
		hdr.CompressionAlgorithm = SMB2CompressionType(int.from_bytes(buff.read(2), byteorder='little', signed = False))
		hdr.Flags  = SMB2CompressionFlags(int.from_bytes(buff.read(2), byteorder='little', signed = False))
		hdr.Offset  = int.from_bytes(buff.read(4), byteorder='little', signed = False)
		return hdr
