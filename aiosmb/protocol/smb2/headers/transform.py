import enum
import io
	
#https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/d6ce2327-a4c9-4793-be66-7b5bad2175fa
class SMB2Header_TRANSFORM:
	def __init__(self):
		self.ProtocolId = b'\xFDSMB'
		self.Signature = None
		self.Nonce = None
		self.OriginalMessageSize = None
		self.Reserved = None
		self.EncryptionAlgorithm = None
		self.SessionId = None
		
	@staticmethod
	def from_buffer(buff):
		hdr = SMB2Header_COMPRESSION_TRANSFORM()
		hdr.ProtocolId = buff.read(4)
		assert hdr.ProtocolId == b'\xFDSMB'
		hdr.Signature  = buff.read(16)
		hdr.Nonce  = buff.read(16)
		hdr.OriginalMessageSize  = int.from_bytes(buff.read(4), byteorder='little', signed = False)
		hdr.Reserved  = int.from_bytes(buff.read(2), byteorder='little', signed = False)
		hdr.EncryptionAlgorithm = int.from_bytes(buff.read(2), byteorder='little', signed = False)
		hdr.SessionId = int.from_bytes(buff.read(8), byteorder='little', signed = False)
		return hdr

