import io
import enum

from aiosmb.wintypes.access_mask import *

class ReadFlag(enum.IntFlag):
	SMB2_READFLAG_READ_UNBUFFERED = 0x01 #The data is read directly from the underlying storage.
	SMB2_READFLAG_REQUEST_COMPRESSED = 0x02 #The server is requested to compress the read response when responding to the request. This flag is not valid for the SMB 2.0.2, 2.1, 3.0 and 3.0.2 dialects<53>.

class Channel(enum.Enum):
	SMB2_CHANNEL_NONE = 0x00000000 #No channel information is present in the request. The ReadChannelInfoOffset and ReadChannelInfoLength fields MUST be set to 0 by the client and MUST be ignored by the server.
	SMB2_CHANNEL_RDMA_V1 = 0x00000001 #One or more SMB_DIRECT_BUFFER_DESCRIPTOR_V1 structures as specified in [MS-SMBD] section 2.2.3.1 are present in the channel information specified by ReadChannelInfoOffset and ReadChannelInfoLength fields.
	SMB2_CHANNEL_RDMA_V1_INVALIDATE = 0x00000002 #This flag is not valid for the SMB 3.0 dialect. One or more SMB_DIRECT_BUFFER_DESCRIPTOR_V1 structures, as specified in [MS-SMBD] section 2.2.3.1, are present in the channel information specified by the ReadChannelInfoOffset and ReadChannelInfoLength fields. The server is requested to perform remote invalidation when responding to the request as specified in [MS-SMBD] section 3.1.4.2.

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/320f04f3-1b28-45cd-aaa1-9e5aed810dca
class READ_REQ:
	def __init__(self):
		self.StructureSize = 49
		self.Padding = 0x50 #dunno why :(
		self.Flags = 0
		self.Length = None
		self.Offset = None
		self.FileId = None
		self.MinimumCount = None
		self.Channel = Channel.SMB2_CHANNEL_NONE
		self.RemainingBytes = None
		self.ReadChannelInfoOffset = 0
		self.ReadChannelInfoLength = 0
		self.Buffer = None
		
		#high-level variable, not part of the spec!
		#For SMB3 only
		self.ReadChannelInfo = None

	def to_bytes(self):
		if self.ReadChannelInfo:
			self.Buffer = self.ReadChannelInfo.to_bytes()
			self.ReadChannelInfoOffset = 64 + 1+1+4+8+16+4+4+4+2+2
			self.ReadChannelInfoLength = len(self.ReadChannelInfo.to_bytes())
		
		t  = self.StructureSize.to_bytes(2, byteorder='little', signed = False)
		t += self.Padding.to_bytes(1, byteorder='little', signed = False)
		t += self.Flags.to_bytes(1, byteorder='little', signed = False)
		t += self.Length.to_bytes(4, byteorder='little', signed = False)
		t += self.Offset.to_bytes(8, byteorder='little', signed = False)
		t += self.FileId.to_bytes(16, byteorder='little', signed = False)
		t += self.MinimumCount.to_bytes(4, byteorder='little', signed = False)
		t += self.Channel.value.to_bytes(4, byteorder='little', signed = False)
		t += self.RemainingBytes.to_bytes(4, byteorder='little', signed = False)
		t += self.ReadChannelInfoOffset.to_bytes(2, byteorder='little', signed = False)
		t += self.ReadChannelInfoLength.to_bytes(2, byteorder='little', signed = False)
		if self.ReadChannelInfoOffset > 0:
			t += self.Buffer
		else:
			t += b'\x00' #dont ask me why...
		return t

	@staticmethod
	def from_bytes(bbuff):
		return READ_REQ.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		msg = READ_REQ()
		msg.StructureSize   = int.from_bytes(buff.read(2), byteorder='little')
		assert msg.StructureSize == 49
		msg.Padding = int.from_bytes(buff.read(1), byteorder='little')
		msg.Flags = ReadFlag(int.from_bytes(buff.read(1), byteorder='little'))
		msg.Length = int.from_bytes(buff.read(4), byteorder = 'little')
		msg.Offset = int.from_bytes(buff.read(8), byteorder = 'little')
		msg.FileId = int.from_bytes(buff.read(16), byteorder = 'little')
		msg.MinimumCount = int.from_bytes(buff.read(4), byteorder = 'little')
		msg.Channel = Channel(int.from_bytes(buff.read(4), byteorder = 'little'))
		msg.RemainingBytes = int.from_bytes(buff.read(4), byteorder = 'little')
		msg.ReadChannelInfoOffset = int.from_bytes(buff.read(2), byteorder = 'little')
		msg.ReadChannelInfoLength = int.from_bytes(buff.read(2), byteorder = 'little')

		if msg.ReadChannelInfoOffset > 0:
			buff.seek(msg.ReadChannelInfoOffset, io.SEEK_SET)
			msg.Buffer= buff.read(msg.ReadChannelInfoLength)
			
			#TODO: correct parsing in SMB3!
			msg.ReadChannelInfo = msg.Buffer.read()
		return msg

	def __repr__(self):
		t = '==== SMB2 READ REQ ====\r\n'
		t += 'StructureSize: %s\r\n' % self.StructureSize
		t += 'Padding: %s\r\n' % self.Padding
		t += 'Flags: %s\r\n' % self.Flags
		t += 'Length: %s\r\n' % self.Length
		t += 'Offset: %s\r\n' % self.Offset
		t += 'FileId: %s\r\n' % self.FileId
		t += 'MinimumCount: %s\r\n' % self.MinimumCount
		t += 'Channel: %s\r\n' % self.Channel
		t += 'RemainingBytes: %s\r\n' % self.RemainingBytes
		t += 'ReadChannelInfoOffset: %s\r\n' % self.ReadChannelInfoOffset
		t += 'ReadChannelInfoLength: %s\r\n' % self.ReadChannelInfoLength
		return t
		
		
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/3e3d2f2c-0e2f-41ea-ad07-fbca6ffdfd90
class READ_REPLY:
	def __init__(self):
		self.StructureSize = 17
		self.DataOffset = None
		self.Reserved = 0
		self.DataLength = None
		self.DataRemaining = None
		self.Reserved2 = 0
		self.Buffer  = None

	def to_bytes(self):
		#todo
		pass

	@staticmethod
	def from_bytes(bbuff):
		return READ_REPLY.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		msg = READ_REPLY()
		msg.StructureSize   = int.from_bytes(buff.read(2), byteorder='little')
		assert msg.StructureSize == 17
		msg.DataOffset = int.from_bytes(buff.read(1), byteorder='little')
		msg.Reserved  = int.from_bytes(buff.read(1), byteorder='little')
		msg.DataLength = int.from_bytes(buff.read(4), byteorder = 'little')
		msg.DataRemaining = int.from_bytes(buff.read(4), byteorder = 'little')
		msg.Reserved2 = int.from_bytes(buff.read(4), byteorder = 'little')
		
		buff.seek(msg.DataOffset, io.SEEK_SET)
		msg.Buffer= buff.read(msg.DataLength)
		return msg

	def __repr__(self):
		t = '==== SMB2 READ REPLY ====\r\n'
		t += 'StructureSize: %s\r\n' % self.StructureSize
		t += 'DataOffset: %s\r\n' % self.DataOffset
		t += 'DataLength: %s\r\n' % self.DataLength
		t += 'DataRemaining: %s\r\n' % self.DataRemaining
		t += 'Buffer: %s\r\n' % self.Buffer
		return t