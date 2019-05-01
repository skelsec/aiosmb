import enum
import io

from aiosmb.protocol.smb2.command_codes import SMB2Command
from aiosmb.commons.ntstatus import NTStatus

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/ea4560b7-90da-4803-82b5-344754b92a79
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/fb188936-5050-48d3-b350-dc43059638a4

class SMB2HeaderFlag(enum.IntFlag):
	SMB2_FLAGS_SERVER_TO_REDIR    = 0x00000001  # When set, indicates the message is a response rather than a request. This MUST be set on responses sent from the server to the client, and MUST NOT be set on requests sent from the client to the server.
	SMB2_FLAGS_ASYNC_COMMAND      = 0x00000002  # When set, indicates that this is an ASYNC SMB2 header. Always set for headers of the form described in this section.
	SMB2_FLAGS_RELATED_OPERATIONS = 0x00000004
	SMB2_FLAGS_SIGNED             = 0x00000008  # When set, indicates that this packet has been signed. The use of this flag is as specified in section 3.1.5.1.
	SMB2_FLAGS_PRIORITY_MASK      = 0x00000070  # This flag is only valid for the SMB 3.1.1 dialect. It is a mask for the requested I/O priority of the request, and it MUST be a value in the range 0 to 7.
	SMB2_FLAGS_DFS_OPERATIONS     = 0x10000000  # When set, indicates that this command is a Distributed File System (DFS) operation. The use of this flag is as specified in section 3.3.5.9.
	SMB2_FLAGS_REPLAY_OPERATION   = 0x20000000

class SMB2Header_ASYNC:
	def __init__(self):
		self.ProtocolId    = None
		self.StructureSize = None
		self.CreditCharge  = None
		self.Status        = None  # In a request, this field is interpreted in different ways depending on the SMB2 dialect.
		self.Command       = None
		self.Credit        = None
		self.Flags         = None
		self.NextCommand   = None
		self.MessageId     = None
		self.AsyncId       = None
		self.SessionId     = None
		self.Signature     = None

	@staticmethod
	def from_buffer(buff):
		hdr = SMB2Header_ASYNC()
		hdr.ProtocolId = buff.read(4)
		assert hdr.ProtocolId == b'\xFESMB'
		hdr.StructureSize = int.from_bytes(buff.read(2), byteorder='little', signed = False)
		assert hdr.StructureSize == 64
		hdr.CreditCharge = int.from_bytes(buff.read(2), byteorder='little', signed = False)
		hdr.Status = NTStatus(int.from_bytes(buff.read(4), byteorder='little', signed = False))
		hdr.Command = SMB2Command(int.from_bytes(buff.read(2), byteorder='little', signed = False))
		hdr.Credit =  int.from_bytes(buff.read(2), byteorder='little', signed = False)
		hdr.Flags =  SMB2HeaderFlag(int.from_bytes(buff.read(4), byteorder='little', signed = False))
		hdr.NextCommand = int.from_bytes(buff.read(4), byteorder='little', signed = False)
		hdr.MessageId = int.from_bytes(buff.read(8), byteorder='little', signed = False)
		hdr.AsyncId = buff.read(8)
		hdr.SessionId = buff.read(8)
		hdr.Signature = buff.read(16)
		return hdr

	@staticmethod
	def construct(cmd, flags, msgid, Credit = 0, NextCommand=0, CreditCharge = 0, 
					Signature=b'\x00'*16,
					AsyncId=b'\x00'*8, SessionId = b'\x00'*8, 
					status = NTStatus.STATUS_SUCCESS):
		hdr = SMB2Header_ASYNC()
		hdr.ProtocolId = b'\xFESMB'
		hdr.StructureSize = 64
		hdr.CreditCharge = CreditCharge
		hdr.Status = status
		hdr.Command = cmd
		hdr.Credit =  Credit
		hdr.Flags =  flags
		hdr.NextCommand = NextCommand
		hdr.MessageId = msgid
		hdr.AsyncId = AsyncId
		hdr.SessionId = SessionId
		hdr.Signature = Signature

		return hdr

	def to_bytes(self):
		t  = self.ProtocolId
		t += self.StructureSize.to_bytes(2, byteorder = 'little', signed=False)
		t += self.CreditCharge.to_bytes(2, byteorder = 'little', signed=False)
		t += self.Status.value.to_bytes(4, byteorder = 'little', signed=False)
		t += self.Command.value.to_bytes(2, byteorder = 'little', signed=False)
		t += self.Credit.to_bytes(2, byteorder = 'little', signed=False)
		t += self.Flags.to_bytes(4, byteorder = 'little', signed=False)
		t += self.NextCommand.to_bytes(4, byteorder = 'little', signed=False)
		t += self.MessageId.to_bytes(8, byteorder = 'little', signed=False)
		t += self.AsyncId
		t += self.SessionId
		t += self.Signature
		return t

	def __repr__(self):
		t = '===SMB2 HEADER ASYNC===\r\n'
		t += 'ProtocolId: %s\r\n' % self.ProtocolId
		t += 'StructureSize: %s\r\n' % self.StructureSize
		t += 'CreditCharge: %s\r\n' % self.CreditCharge
		t += 'Status: %s\r\n' % self.Status.name
		t += 'Command: %s\r\n' % self.Command.name
		t += 'Credit: %s\r\n' % self.Credit
		t += 'Flags: %s\r\n' % self.Flags
		t += 'NextCommand: %s\r\n' % self.NextCommand
		t += 'MessageId: %s\r\n' % self.MessageId
		t += 'AsyncId: %s\r\n' % self.AsyncId
		t += 'SessionId: %s\r\n' % self.SessionId
		t += 'Signature: %s\r\n' % self.Signature
		return t


class SMB2Header_SYNC():
	def __init__(self):
		self.ProtocolId    = None
		self.StructureSize = None
		self.CreditCharge  = None
		self.Status        = None
		self.Command       = None
		self.Credit        = None
		self.Flags         = None
		self.NextCommand   = None
		self.MessageId     = None
		self.Reserved      = None
		self.TreeId        = None
		self.SessionId     = None
		self.Signature     = None

	@staticmethod
	def from_buffer(buff):
		hdr = SMB2Header_SYNC()
		hdr.ProtocolId = buff.read(4)
		assert hdr.ProtocolId == b'\xFESMB'
		hdr.StructureSize = int.from_bytes(buff.read(2), byteorder='little', signed = False)
		assert hdr.StructureSize == 64
		hdr.CreditCharge = int.from_bytes(buff.read(2), byteorder='little', signed = False)
		hdr.Status      = NTStatus(int.from_bytes(buff.read(4), byteorder='little', signed = False))
		hdr.Command     = SMB2Command(int.from_bytes(buff.read(2), byteorder='little', signed = False))
		hdr.Credit      = int.from_bytes(buff.read(2), byteorder='little', signed = False)
		hdr.Flags       = SMB2HeaderFlag(int.from_bytes(buff.read(4), byteorder='little', signed = False))
		hdr.NextCommand = int.from_bytes(buff.read(4), byteorder='little', signed = False)
		hdr.MessageId   = int.from_bytes(buff.read(8), byteorder='little', signed = False)
		hdr.Reserved    = buff.read(4)
		hdr.TreeId      = buff.read(4)
		hdr.SessionId   = buff.read(8)
		hdr.Signature   = buff.read(16)
		return hdr

	def to_bytes(self):
		t  = self.ProtocolId
		t += self.StructureSize.to_bytes(2, byteorder = 'little', signed=False)
		t += self.CreditCharge.to_bytes(2, byteorder = 'little', signed=False)
		t += self.Status.to_bytes(4, byteorder = 'little', signed=False)
		t += self.Command.to_bytes(2, byteorder = 'little', signed=False)
		t += self.Credit.to_bytes(2, byteorder = 'little', signed=False)
		t += self.Flags.to_bytes(4, byteorder = 'little', signed=False)
		t += self.NextCommand.to_bytes(4, byteorder = 'little', signed=False)
		t += self.MessageId.to_bytes(8, byteorder = 'little', signed=False)
		t += self.Reserved
		t += self.TreeId
		t += self.SessionId
		t += self.Signature
		return t

	def __repr__(self):
		t = '===SMB2 HEADER SYNC===\r\n'
		t += 'ProtocolId:    %s\r\n' % self.ProtocolId
		t += 'StructureSize: %s\r\n' % self.StructureSize
		t += 'CreditCharge:  %s\r\n' % self.CreditCharge
		t += 'Status:    %s\r\n' % self.Status.name
		t += 'Command:   %s\r\n' % self.Command.name
		t += 'Credit:    %s\r\n' % self.Credit
		t += 'Flags:     %s\r\n' % self.Flags
		t += 'NextCommand: %s\r\n' % self.NextCommand
		t += 'MessageId: %s\r\n' % self.MessageId
		t += 'Reserved:  %s\r\n' % self.Reserved
		t += 'TreeId:    %s\r\n' % self.TreeId
		t += 'SessionId: %s\r\n' % self.SessionId
		t += 'Signature: %s\r\n' % self.Signature
		return t
