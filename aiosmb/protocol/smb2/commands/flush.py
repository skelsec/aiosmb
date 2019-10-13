import io
import enum

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e494678b-b1fc-44a0-b86e-8195acf74ad7
class FLUSH_REQ:
	def __init__(self):
		self.StructureSize = 24
		self.Reserved1 = 0
		self.Reserved2 = 0
		self.FileId = None
		
	def to_bytes(self):
		t  = self.StructureSize.to_bytes(2, byteorder='little', signed = False)
		t += self.Reserved1.to_bytes(2, byteorder='little', signed = False)
		t += self.Reserved2.to_bytes(4, byteorder='little', signed = False)
		t += self.FileId.to_bytes(16, byteorder='little', signed = False)
		return t

	@staticmethod
	def from_bytes(bbuff):
		return FLUSH_REQ.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		msg = FLUSH_REQ()
		msg.StructureSize   = int.from_bytes(buff.read(2), byteorder='little')
		assert msg.StructureSize == 24
		msg.Reserved1  = int.from_bytes(buff.read(2), byteorder='little')
		msg.Reserved2  = int.from_bytes(buff.read(4), byteorder='little')
		msg.FileId  = int.from_bytes(buff.read(16), byteorder='little')
		return msg

	def __repr__(self):
		t = '==== SMB2 FLUSH REQ ====\r\n'
		t += 'StructureSize: %s\r\n' % self.StructureSize
		t += 'FileId: %s\r\n' % self.FileId
		return t
		
		
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/42f78e6a-e25f-48f5-8f08-b4f1bb4c4fa4
class FLUSH_REPLY:
	def __init__(self):
		self.StructureSize = 4
		self.Reserved = 0
		
	def to_bytes(self):
		t  = self.StructureSize.to_bytes(2, byteorder='little', signed = False)
		t += self.Reserved.to_bytes(2, byteorder='little', signed = False)
		return t

	@staticmethod
	def from_bytes(bbuff):
		return FLUSH_REPLY.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		msg = FLUSH_REPLY()
		msg.StructureSize   = int.from_bytes(buff.read(2), byteorder='little')
		assert msg.StructureSize == 4
		msg.Reserved  = int.from_bytes(buff.read(2), byteorder='little')
		return msg

	def __repr__(self):
		t = '==== SMB2 FLUSH REPLY ====\r\n'
		t += 'StructureSize: %s\r\n' % self.StructureSize
		return t