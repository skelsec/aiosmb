import io
import enum

from aiosmb.wintypes.fscc.FileAttributes import *

class CloseFlag(enum.IntFlag):
	NONE = 0
	SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB = 0x0001 #If set, the server MUST set the attribute fields in the response, as specified in section 2.2.16, to valid values. If not set, the client MUST NOT use the values that are returned in the response.

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/f84053b0-bcb2-4f85-9717-536dae2b02bd
class CLOSE_REQ:
	def __init__(self):
		self.StructureSize = 24
		self.Flags = 0
		self.Reserved = 0
		self.FileId = None
		
	def to_bytes(self):
		t  = self.StructureSize.to_bytes(2, byteorder='little', signed = False)
		t += self.Flags.value.to_bytes(2, byteorder='little', signed = False)
		t += self.Reserved.to_bytes(4, byteorder='little', signed = False)
		t += self.FileId.to_bytes(16, byteorder='little', signed = False)
		return t

	@staticmethod
	def from_bytes(bbuff):
		return CLOSE_REQ.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		msg = CLOSE_REQ()
		msg.StructureSize   = int.from_bytes(buff.read(2), byteorder='little')
		assert msg.StructureSize == 24
		msg.Flags  = CloseFlag(int.from_bytes(buff.read(2), byteorder='little'))
		msg.Reserved  = int.from_bytes(buff.read(4), byteorder='little')
		msg.FileId  = int.from_bytes(buff.read(16), byteorder='little')
		return msg

	def __repr__(self):
		t = '==== SMB2 CLOSE REQ ====\r\n'
		t += 'StructureSize: %s\r\n' % self.StructureSize
		t += 'Flags: %s\r\n' % self.Flags
		t += 'FileId: %s\r\n' % self.FileId
		return t
		
		
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/c0c15c57-3f3e-452b-b51c-9cc650a13f7b
class CLOSE_REPLY:
	def __init__(self):
		self.StructureSize = 60
		self.Flags = None
		self.Reserved = 0
		self.CreationTime = None
		self.LastAccessTime = None
		self.LastWriteTime = None
		self.ChangeTime = None
		self.AllocationSize = None
		self.EndofFile = None
		self.FileAttributes = None
		
	def to_bytes(self):
		t  = self.StructureSize.to_bytes(2, byteorder='little', signed = False)
		t += self.Flags.value.to_bytes(2, byteorder='little', signed = False)
		t += self.Reserved.to_bytes(4, byteorder='little', signed = False)
		t += self.CreationTime.to_bytes(8, byteorder='little', signed = False)
		t += self.LastAccessTime.to_bytes(8, byteorder='little', signed = False)
		t += self.LastWriteTime.to_bytes(8, byteorder='little', signed = False)
		t += self.ChangeTime.to_bytes(8, byteorder='little', signed = False)
		t += self.AllocationSize.to_bytes(8, byteorder='little', signed = False)
		t += self.EndofFile.to_bytes(8, byteorder='little', signed = False)
		t += self.FileAttributes.to_bytes(4, byteorder='little', signed = False)
		return t

	@staticmethod
	def from_bytes(bbuff):
		return CLOSE_REPLY.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		msg = CLOSE_REPLY()
		msg.StructureSize   = int.from_bytes(buff.read(2), byteorder='little')
		assert msg.StructureSize == 60
		msg.Flags  = CloseFlag(int.from_bytes(buff.read(2), byteorder='little'))
		msg.Reserved  = int.from_bytes(buff.read(4), byteorder='little')
		msg.CreationTime  = int.from_bytes(buff.read(8), byteorder='little')
		msg.LastAccessTime  = int.from_bytes(buff.read(8), byteorder='little')
		msg.LastWriteTime  = int.from_bytes(buff.read(8), byteorder='little')
		msg.ChangeTime  = int.from_bytes(buff.read(8), byteorder='little')
		msg.AllocationSize  = int.from_bytes(buff.read(8), byteorder='little')
		msg.EndofFile  = int.from_bytes(buff.read(8), byteorder='little')
		msg.FileAttributes  = FileAttributes(int.from_bytes(buff.read(4), byteorder='little'))
		return msg

	def __repr__(self):
		t = '==== SMB2 CLOSE REPLY ====\r\n'
		t += 'StructureSize: %s\r\n' % self.StructureSize
		return t