import io
import enum

from aiosmb.wintypes.access_mask import *
from aiosmb.protocol.smb2.commands.read import Channel

class WriteFlag(enum.IntFlag):
	NONE = 0
	WRITE_THROUGH = 0x00000001 #The server performs File write-through on the write operation. This value is not valid for the SMB 2.0.2 dialect.
	WRITE_UNBUFFERED = 0x00000002 #File buffering is not performed. This bit is not valid for the SMB 2.0.2, 2.1, and 3.0 dialects.


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e7046961-3318-4350-be2a-a8d69bb59ce8
class WRITE_REQ:
	def __init__(self):
		self.StructureSize = 49
		self.DataOffset = None
		self.Length = None
		self.Offset = None
		self.FileId = None
		self.Channel = Channel.SMB2_CHANNEL_NONE
		self.RemainingBytes = 0
		self.WriteChannelInfoOffset = 0
		self.WriteChannelInfoLength = 0
		self.Flags = WriteFlag.NONE
		self.Buffer = None
		
		#high-level variable, not part of the spec!
		#For SMB3 only
		self.WriteChannelInfo = None
		self.Data = None

	def to_bytes(self):
		self.DataOffset = 64 + 2+2+4+8+16+4+4+2+2+4
		if self.Data:
			self.Length = len(self.Data)
			self.Buffer = self.Data
		else:
			self.Length = 0 
			self.Buffer = b''
			
		if self.WriteChannelInfo:
			self.Buffer += self.WriteChannelInfo.to_bytes()
			self.WriteChannelInfoOffset = self.DataOffset + len(self.Buffer)
			self.WriteChannelInfoLength = len(self.WriteChannelInfo.to_bytes())
		
		t  = self.StructureSize.to_bytes(2, byteorder='little', signed = False)
		t += self.DataOffset.to_bytes(2, byteorder='little', signed = False)
		t += self.Length.to_bytes(4, byteorder='little', signed = False)
		t += self.Offset.to_bytes(8, byteorder='little', signed = False)
		t += self.FileId.to_bytes(16, byteorder='little', signed = False)
		t += self.Channel.value.to_bytes(4, byteorder='little', signed = False)
		t += self.RemainingBytes.to_bytes(4, byteorder='little', signed = False)
		t += self.WriteChannelInfoOffset.to_bytes(2, byteorder='little', signed = False)
		t += self.WriteChannelInfoLength.to_bytes(2, byteorder='little', signed = False)
		t += self.Flags.value.to_bytes(4, byteorder='little', signed = False)
		
		t += self.Buffer
		return t

	@staticmethod
	def from_bytes(bbuff):
		return WRITE_REQ.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		msg = WRITE_REQ()
		msg.StructureSize   = int.from_bytes(buff.read(2), byteorder='little')
		assert msg.StructureSize == 49
		msg.DataOffset = int.from_bytes(buff.read(2), byteorder='little')
		msg.Length  = int.from_bytes(buff.read(4), byteorder='little')
		msg.Offset = int.from_bytes(buff.read(8), byteorder = 'little')
		msg.FileId = int.from_bytes(buff.read(16), byteorder = 'little')
		msg.Channel = Channel(int.from_bytes(buff.read(4), byteorder = 'little'))
		msg.RemainingBytes = int.from_bytes(buff.read(4), byteorder = 'little')
		msg.WriteChannelInfoOffset  = int.from_bytes(buff.read(2), byteorder = 'little')
		msg.WriteChannelInfoLength  = int.from_bytes(buff.read(2), byteorder = 'little')
		msg.Flags  = WriteFlag(int.from_bytes(buff.read(4), byteorder = 'little'))
		
		buff.seek(msg.DataOffset, io.SEEK_SET)
		msg.Data = buff.read(msg.Length)

		if msg.WriteChannelInfoOffset > 0:
			#TODO: correct parsing in SMB3!
			buff.seek(msg.WriteChannelInfoOffset, io.SEEK_SET)
			msg.WriteChannelInfo = buff.read(msg.WriteChannelInfoLength)
		
		return msg

	def __repr__(self):
		t = '==== SMB2 WRITE REQ ====\r\n'
		t += 'StructureSize: %s\r\n' % self.StructureSize
		t += 'DataOffset: %s\r\n' % self.DataOffset
		t += 'Length: %s\r\n' % self.Length
		t += 'Offset: %s\r\n' % self.Offset
		t += 'FileId: %s\r\n' % self.FileId
		t += 'Channel: %s\r\n' % self.Channel
		t += 'RemainingBytes: %s\r\n' % self.RemainingBytes
		t += 'WriteChannelInfoOffset: %s\r\n' % self.WriteChannelInfoOffset
		t += 'WriteChannelInfoLength: %s\r\n' % self.WriteChannelInfoLength
		t += 'Flags: %s\r\n' % self.Flags
		t += 'Data: %s\r\n' % self.Data
		t += 'WriteChannelInfo: %s\r\n' % self.WriteChannelInfo
		return t
		
		
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/7b80a339-f4d3-4575-8ce2-70a06f24f133
class WRITE_REPLY:
	def __init__(self):
		self.StructureSize = 17
		self.Reserved = 0
		self.Count = None
		self.Remaining = None
		self.WriteChannelInfoOffset = 0
		self.WriteChannelInfoLength = 0

	def to_bytes(self):
		#todo
		pass

	@staticmethod
	def from_bytes(bbuff):
		return WRITE_REPLY.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		msg = WRITE_REPLY()
		msg.StructureSize   = int.from_bytes(buff.read(2), byteorder='little')
		assert msg.StructureSize == 17
		msg.Reserved  = int.from_bytes(buff.read(2), byteorder='little')
		msg.Count  = int.from_bytes(buff.read(4), byteorder='little')
		msg.Remaining  = int.from_bytes(buff.read(4), byteorder = 'little')
		msg.WriteChannelInfoOffset  = int.from_bytes(buff.read(2), byteorder = 'little')
		msg.WriteChannelInfoLength  = int.from_bytes(buff.read(2), byteorder = 'little')
		
		return msg

	def __repr__(self):
		t = '==== SMB2 WRITE REPLY ====\r\n'
		t += 'StructureSize: %s\r\n' % self.StructureSize
		t += 'Count: %s\r\n' % self.Count
		t += 'Remaining: %s\r\n' % self.Remaining
		t += 'WriteChannelInfoOffset: %s\r\n' % self.WriteChannelInfoOffset
		t += 'WriteChannelInfoLength: %s\r\n' % self.WriteChannelInfoLength
		return t