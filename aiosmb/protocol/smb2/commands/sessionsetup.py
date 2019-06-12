import io
import enum

from aiosmb.protocol.smb2.commands.negotiate import NegotiateSecurityMode

class SessionSetupFlag(enum.IntFlag):
	SMB2_SESSION_FLAG_BINDING = 0x01


class SessionSetupCapabilities(enum.IntFlag):
	SMB2_GLOBAL_CAP_DFS     = 0x00000001 #When set, indicates that the client supports the Distributed File System (DFS).
	SMB2_GLOBAL_CAP_UNUSED1 = 0x00000002 #SHOULD be set to zero, and server MUST ignore.
	SMB2_GLOBAL_CAP_UNUSED2 = 0x00000004 #SHOULD be set to zero and server MUST ignore.
	SMB2_GLOBAL_CAP_UNUSED3 = 0x00000008 #SHOULD be set to zero and server MUST ignore.

# https://msdn.microsoft.com/en-us/library/cc246563.aspx
class SESSION_SETUP_REQ:
	def __init__(self):
		self.StructureSize = 25
		self.Flags = None
		self.SecurityMode = None
		self.Capabilities = None
		self.Channel = None
		self.SecurityBufferOffset = None
		self.SecurityBufferLength = None
		self.PreviousSessionId = None
		self.Buffer = None
		
	def to_bytes(self):
		self.SecurityBufferLength = len(self.Buffer)
		self.SecurityBufferOffset = 64 + 2 + 1 + 1 +4 +4 +2 +2 +8
		
		t  = self.StructureSize.to_bytes(2, byteorder='little', signed = False)
		t += self.Flags.to_bytes(1, byteorder='little', signed = False)
		t += self.SecurityMode.to_bytes(1, byteorder='little', signed = False)
		t += self.Capabilities.to_bytes(4, byteorder='little', signed = False)
		t += self.Channel.to_bytes(4, byteorder='little', signed = False)
		t += self.SecurityBufferOffset.to_bytes(2, byteorder='little', signed = False)
		t += self.SecurityBufferLength.to_bytes(2, byteorder='little', signed = False)
		t += self.PreviousSessionId.to_bytes(8, byteorder='little', signed = False)
		t += self.Buffer
		
		return t

	@staticmethod
	def from_bytes(bbuff):
		return SESSION_SETUP_REQ.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		msg = SESSION_SETUP_REQ()
		msg.StructureSize   = int.from_bytes(buff.read(2), byteorder='little')
		assert msg.StructureSize == 25
		msg.Flags = SessionSetupFlag(int.from_bytes(buff.read(1), byteorder='little'))
		msg.SecurityMode = NegotiateSecurityMode(int.from_bytes(buff.read(1), byteorder='little'))
		msg.Capabilities = SessionSetupCapabilities(int.from_bytes(buff.read(4), byteorder = 'little'))
		msg.Channel      = int.from_bytes(buff.read(4), byteorder = 'little')
		msg.SecurityBufferOffset = int.from_bytes(buff.read(2), byteorder = 'little')
		msg.SecurityBufferLength = int.from_bytes(buff.read(2), byteorder = 'little')
		msg.PreviousSessionId    = buff.read(8)

		buff.seek(msg.SecurityBufferOffset, io.SEEK_SET)
		msg.Buffer= buff.read(msg.SecurityBufferLength)
		return msg

	def __repr__(self):
		t = '==== SMB2 SESSION SETUP REQ ====\r\n'
		t += 'StructureSize: %s\r\n' % self.StructureSize
		t += 'Flags: %s\r\n' % repr(self.Flags)
		t += 'SecurityMode: %s\r\n' % self.SecurityMode
		t += 'Capabilities: %s\r\n' % self.Capabilities
		t += 'Channel: %s\r\n' % self.Channel
		t += 'SecurityBufferOffset: %s\r\n' % self.SecurityBufferOffset
		t += 'SecurityBufferLength: %s\r\n' % self.SecurityBufferLength
		t += 'PreviousSessionId: %s\r\n' % self.PreviousSessionId
		t += 'Buffer: %s\r\n' % self.Buffer
		return t


# https://msdn.microsoft.com/en-us/library/cc246564.aspx
class SessionFlags(enum.IntFlag):
	SMB2_SESSION_FLAG_IS_GUEST = 0x0001 #If set, the client has been authenticated as a guest user.
	SMB2_SESSION_FLAG_IS_NULL = 0x0002 #If set, the client has been authenticated as an anonymous user.
	SMB2_SESSION_FLAG_ENCRYPT_DATA = 0x0004 #If set, the server requires encryption of messages on this session, per the conditions specified in section 3.3.5.2.9. This flag is only valid for the SMB 3.x dialect family.


# https://msdn.microsoft.com/en-us/library/cc246564.aspx
class SESSION_SETUP_REPLY():
	def __init__(self):
		self.StructureSize = 9
		self.SessionFlags = None
		self.SecurityBufferOffset = None
		self.SecurityBufferLength = None
		self.Buffer = None

	@staticmethod
	def from_bytes(bbuff):
		return SESSION_SETUP_REPLY.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		msg = SESSION_SETUP_REPLY()
		msg.StructureSize   = int.from_bytes(buff.read(2), byteorder='little')
		assert msg.StructureSize == 9
		msg.SessionFlags = SessionFlags(int.from_bytes(buff.read(2), byteorder = 'little'))
		msg.SecurityBufferOffset = int.from_bytes(buff.read(2), byteorder = 'little')
		msg.SecurityBufferLength = int.from_bytes(buff.read(2), byteorder = 'little')
		msg.Buffer = buff.read(msg.SecurityBufferLength)
		return msg

	def to_bytes(self):
		self.SecurityBufferOffset = 0x48
		self.SecurityBufferLength = len(self.Buffer)

		t  = self.StructureSize.to_bytes(2, byteorder = 'little', signed=False)
		t += self.SessionFlags.to_bytes(2, byteorder = 'little', signed=False)
		t += self.SecurityBufferOffset.to_bytes(2, byteorder = 'little', signed=False)
		t += self.SecurityBufferLength.to_bytes(2, byteorder = 'little', signed=False)
		t += self.Buffer
		return t

	def __repr__(self):
		t = '==== SMB2 SESSION SETUP REPLY ====\r\n'
		t += 'StructureSize: %s\r\n' % self.StructureSize
		t += 'SessionFlags: %s\r\n' % repr(self.SessionFlags)
		t += 'SecurityBufferOffset: %s\r\n' % self.SecurityBufferOffset
		t += 'SecurityBufferLength: %s\r\n' % self.SecurityBufferLength
		t += 'Buffer: %s\r\n' % self.Buffer
		return t
