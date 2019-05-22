import io
import enum

#SMB 3.1.1 ONLY! Otherwise it's 0 as reserved!
class TreeConnectFlag(enum.IntFlag):
	SMB2_TREE_CONNECT_FLAG_CLUSTER_RECONNECT = 0x0001
	SMB2_TREE_CONNECT_FLAG_REDIRECT_TO_OWNER = 0x0002
	SMB2_TREE_CONNECT_FLAG_EXTENSION_PRESENT = 0x0004


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/832d2130-22e8-4afb-aafd-b30bb0901798
class TREE_CONNECT_REQ:
	def __init__(self):
		self.StructureSize = 9
		self.Flags = None
		self.PathOffset = None
		self.PathLength = None
		self.Buffer = None
		
		#high-level variable, not part of the spec!
		self.Path = None

	def to_bytes(self):
		if self.Path:
			self.Buffer = self.Path.encode('utf-16-le')
		
		self.PathLength = len(self.Buffer)
		self.PathOffset = 64 + 2 + 2 + 2 + 2 
		
		t  = self.StructureSize.to_bytes(2, byteorder='little', signed = False)
		t += self.Flags.to_bytes(2, byteorder='little', signed = False)
		t += self.PathOffset.to_bytes(2, byteorder='little', signed = False)
		t += self.PathLength.to_bytes(2, byteorder='little', signed = False)
		t += self.Buffer
		return t

	@staticmethod
	def from_bytes(bbuff):
		return TREE_CONNECT_REQ.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		msg = TREE_CONNECT_REQ()
		msg.StructureSize   = int.from_bytes(buff.read(2), byteorder='little')
		assert msg.StructureSize == 9
		msg.Flags = TreeConnectFlag(int.from_bytes(buff.read(2), byteorder='little'))
		msg.PathOffset = int.from_bytes(buff.read(2), byteorder='little')
		msg.PathLength = int.from_bytes(buff.read(2), byteorder = 'little')

		buff.seek(msg.PathOffset, io.SEEK_SET)
		msg.Buffer= buff.read(msg.PathLength)
		
		msg.Path = msg.Buffer.decode('utf-16-le')
		return msg

	def __repr__(self):
		t = '==== SMB2 TREE CONNECT REQ ====\r\n'
		t += 'StructureSize: %s\r\n' % self.StructureSize
		t += 'Flags: %s\r\n' % repr(self.Flags)
		t += 'PathOffset: %s\r\n' % self.PathOffset
		t += 'PathLength: %s\r\n' % self.PathLength
		t += 'Path: %s\r\n' % self.Path
		return t