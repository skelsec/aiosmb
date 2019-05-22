import enum
import io

#https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/78e0c942-ab41-472b-b117-4a95ebe88271
class SMB2CompressionAlgorithms(enum.Enum):
	NONE = 0x0000
	LZNT1 = 0x0001
	LZ77 = 0x0002
	LZ77_HUFFMAN = 0x0003
	
#https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/1d435f21-9a21-4f4c-828e-624a176cf2a0
class SMB2Header_COMPRESSION_TRANSFORM:
	def __init__(self):
		self.ProtocolId = b'\xFCSMB'
		self.OriginalCompressedSegmentSize = None
		self.CompressionAlgorithm = None
		self.Reserved = None
		self.Offset = None
		
	@staticmethod
	def from_buffer(buff):
		hdr = SMB2Header_COMPRESSION_TRANSFORM()
		hdr.ProtocolId = buff.read(4)
		assert hdr.ProtocolId == b'\xFCSMB'
		hdr.OriginalCompressedSegmentSize = int.from_bytes(buff.read(4), byteorder='little', signed = False)
		hdr.CompressionAlgorithm = SMB2CompressionAlgorithms(int.from_bytes(buff.read(2), byteorder='little', signed = False))
		hdr.Reserved  = int.from_bytes(buff.read(2), byteorder='little', signed = False)
		hdr.Offset  = int.from_bytes(buff.read(4), byteorder='little', signed = False)
		return hdr
