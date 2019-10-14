
import enum
import io

from aiosmb.protocol.smb2.command_codes import SMB2Command
from aiosmb.wintypes.ntstatus import NTStatus
from aiosmb.protocol.smb2.headers.common import SMB2HeaderFlag

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/ea4560b7-90da-4803-82b5-344754b92a79

class SMB2Header_ASYNC:
	def __init__(self):
		self.ProtocolId    = b'\xFESMB'
		self.StructureSize = 64
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
					status = NTStatus.SUCCESS):
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