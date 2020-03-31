import enum
import io

from aiosmb.protocol.smb2.commands.negotiate import SMB2Cipher
	
#https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/d6ce2327-a4c9-4793-be66-7b5bad2175fa
class SMB2Header_TRANSFORM:
	def __init__(self):
		self.ProtocolId = b'\xFDSMB'
		self.Signature = b'\x00'*16
		self.Nonce = None
		self.OriginalMessageSize = None
		self.Reserved = 0
		self.EncryptionAlgorithm = None
		self.SessionId = None
	
	def to_bytes(self):
		t = self.ProtocolId
		t += self.Signature
		t += self.Nonce
		t += self.OriginalMessageSize.to_bytes(4, byteorder='little', signed = False)
		t += self.Reserved.to_bytes(2, byteorder='little', signed = False)
		t += self.EncryptionAlgorithm.value.to_bytes(2, byteorder='little', signed = False)
		t += self.SessionId.to_bytes(8, byteorder='little', signed = False)
		return t


	@staticmethod
	def from_buffer(buff):
		hdr = SMB2Header_TRANSFORM()
		hdr.ProtocolId = buff.read(4)
		assert hdr.ProtocolId == b'\xFDSMB'
		hdr.Signature  = buff.read(16)
		hdr.Nonce  = buff.read(16)
		hdr.OriginalMessageSize  = int.from_bytes(buff.read(4), byteorder='little', signed = False)
		hdr.Reserved  = int.from_bytes(buff.read(2), byteorder='little', signed = False)
		hdr.EncryptionAlgorithm = SMB2Cipher(int.from_bytes(buff.read(2), byteorder='little', signed = False))
		hdr.SessionId = int.from_bytes(buff.read(8), byteorder='little', signed = False)
		return hdr

