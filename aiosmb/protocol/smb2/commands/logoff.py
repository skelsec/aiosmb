import io
import enum

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/d939504d-57e2-4c0e-8ad5-1678b6fccca1
class LOGOFF_REQ:
	def __init__(self):
		self.StructureSize = 4
		self.Reserved = 0
		
	def to_bytes(self):
		t  = self.StructureSize.to_bytes(2, byteorder='little', signed = False)
		t += self.Reserved.to_bytes(2, byteorder='little', signed = False)
		return t

	@staticmethod
	def from_bytes(bbuff):
		return LOGOFF_REQ.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		msg = LOGOFF_REQ()
		msg.StructureSize   = int.from_bytes(buff.read(2), byteorder='little')
		assert msg.StructureSize == 4
		msg.Reserved  = int.from_bytes(buff.read(2), byteorder='little')
		return msg

	def __repr__(self):
		t = '==== SMB2 LOGOFF REQ ====\r\n'
		t += 'StructureSize: %s\r\n' % self.StructureSize
		return t
		
		
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/2abe9b3c-c5ab-417f-bcc3-9ab51f2fce35
class LOGOFF_REPLY:
	def __init__(self):
		self.StructureSize = 4
		self.Reserved = 0
		
	def to_bytes(self):
		t  = self.StructureSize.to_bytes(2, byteorder='little', signed = False)
		t += self.Reserved.to_bytes(2, byteorder='little', signed = False)
		return t

	@staticmethod
	def from_bytes(bbuff):
		return LOGOFF_REPLY.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		msg = LOGOFF_REPLY()
		msg.StructureSize   = int.from_bytes(buff.read(2), byteorder='little')
		assert msg.StructureSize == 4
		msg.Reserved  = int.from_bytes(buff.read(2), byteorder='little')
		return msg

	def __repr__(self):
		t = '==== SMB2 LOGOFF REPLY ====\r\n'
		t += 'StructureSize: %s\r\n' % self.StructureSize
		return t