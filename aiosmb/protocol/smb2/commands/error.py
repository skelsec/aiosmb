import io
import enum

# TODO: additional parsing for the error context!

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/d4da8b67-c180-47e3-ba7a-d24214ac4aaa
class ERROR_REPLY:
	def __init__(self):
		self.StructureSize = 9
		self.ErrorContextCount = 0
		self.Reserved = 0
		self.ByteCount = 0
		
		self.ErrorData = None
		
	def to_bytes(self):
		t  = self.StructureSize.to_bytes(2, byteorder='little', signed = False)
		t += self.ErrorContextCount.to_bytes(1, byteorder='little', signed = False)
		t += self.Reserved.to_bytes(1, byteorder='little', signed = False)
		t += self.ByteCount.to_bytes(4, byteorder='little', signed = False)
		if self.ByteCount > 0:
			t += self.ErrorData.to_bytes()
		return t

	@staticmethod
	def from_bytes(bbuff):
		return ERROR_REPLY.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		msg = ERROR_REPLY()
		msg.StructureSize   = int.from_bytes(buff.read(2), byteorder='little')
		assert msg.StructureSize == 9
		msg.ErrorContextCount  = int.from_bytes(buff.read(1), byteorder='little')
		msg.Reserved  = int.from_bytes(buff.read(1), byteorder='little')
		msg.ByteCount  = int.from_bytes(buff.read(4), byteorder='little')
		if msg.ByteCount > 0:
			msg.ErrorData = buff.read(msg.ByteCount)
		return msg

	def __repr__(self):
		t = '==== SMB2 ERROR ====\r\n'
		return t