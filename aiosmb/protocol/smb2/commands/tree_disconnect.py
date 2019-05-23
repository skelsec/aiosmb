import io
import enum

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/8a622ecb-ffee-41b9-b4c4-83ff2d3aba1b
class TREE_DISCONNECT_REQ:
	def __init__(self):
		self.StructureSize = 4
		self.Reserved = 0
		
	def to_bytes(self):
		t  = self.StructureSize.to_bytes(2, byteorder='little', signed = False)
		t += self.Reserved.to_bytes(2, byteorder='little', signed = False)
		return t

	@staticmethod
	def from_bytes(bbuff):
		return TREE_DISCONNECT_REQ.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		msg = TREE_DISCONNECT_REQ()
		msg.StructureSize   = int.from_bytes(buff.read(2), byteorder='little')
		assert msg.StructureSize == 4
		msg.Reserved  = int.from_bytes(buff.read(2), byteorder='little')
		return msg

	def __repr__(self):
		t = '==== SMB2 TREE DISCONNECT REQ ====\r\n'
		t += 'StructureSize: %s\r\n' % self.StructureSize
		return t
		
		
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/aeac92de-8db3-48f8-a8b7-bfee28b9fd9e
class TREE_DISCONNECT_REPLY:
	def __init__(self):
		self.StructureSize = 4
		self.Reserved = 0
		
	def to_bytes(self):
		t  = self.StructureSize.to_bytes(2, byteorder='little', signed = False)
		t += self.Reserved.to_bytes(2, byteorder='little', signed = False)
		return t

	@staticmethod
	def from_bytes(bbuff):
		return TREE_DISCONNECT_REPLY.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		msg = TREE_DISCONNECT_REPLY()
		msg.StructureSize   = int.from_bytes(buff.read(2), byteorder='little')
		assert msg.StructureSize == 4
		msg.Reserved  = int.from_bytes(buff.read(2), byteorder='little')
		return msg

	def __repr__(self):
		t = '==== SMB2 TREE DISCONNECT REPLY ====\r\n'
		t += 'StructureSize: %s\r\n' % self.StructureSize
		return t