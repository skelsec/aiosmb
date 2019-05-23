import io
import enum

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/91913fc6-4ec9-4a83-961b-370070067e63
class CANCEL_REQ:
	def __init__(self):
		self.StructureSize = 4
		self.Reserved = 0
		
	def to_bytes(self):
		t  = self.StructureSize.to_bytes(2, byteorder='little', signed = False)
		t += self.Reserved.to_bytes(2, byteorder='little', signed = False)
		return t

	@staticmethod
	def from_bytes(bbuff):
		return CANCEL_REQ.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		msg = CANCEL_REQ()
		msg.StructureSize   = int.from_bytes(buff.read(2), byteorder='little')
		assert msg.StructureSize == 4
		msg.Reserved  = int.from_bytes(buff.read(2), byteorder='little')
		return msg

	def __repr__(self):
		t = '==== SMB2 CANCEL REQ/REPLY ====\r\n'
		t += 'StructureSize: %s\r\n' % self.StructureSize
		return t