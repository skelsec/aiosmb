import enum
import io

from aiosmb.protocol.smb2.command_codes import SMB2Command
from aiosmb.wintypes.ntstatus import NTStatus
from aiosmb.protocol.smb2.headers.common import SMB2HeaderFlag


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/fb188936-5050-48d3-b350-dc43059638a4
class SMB2Header_SYNC():
	def __init__(self):
		self.ProtocolId    = b'\xFESMB'
		self.StructureSize = 64
		self.CreditCharge  = None
		self.Status        = NTStatus.SUCCESS
		self.Command       = None
		self.CreditReq     = None
		self.Flags         = 0
		self.NextCommand   = 0
		self.MessageId     = None
		self.Reserved      = 0
		self.TreeId        = 0
		self.SessionId     = 0
		self.Signature     = b'\x00'*16

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
		hdr.CreditReq      = int.from_bytes(buff.read(2), byteorder='little', signed = False)
		hdr.Flags       = SMB2HeaderFlag(int.from_bytes(buff.read(4), byteorder='little', signed = False))
		hdr.NextCommand = int.from_bytes(buff.read(4), byteorder='little', signed = False)
		hdr.MessageId   = int.from_bytes(buff.read(8), byteorder='little', signed = False)
		hdr.Reserved    = int.from_bytes(buff.read(4), byteorder='little', signed = False)
		hdr.TreeId      = int.from_bytes(buff.read(4), byteorder='little', signed = False)
		hdr.SessionId   = int.from_bytes(buff.read(8), byteorder='little', signed = False)
		hdr.Signature   = buff.read(16)
		return hdr

	def to_bytes(self):
		t  = self.ProtocolId
		t += self.StructureSize.to_bytes(2, byteorder = 'little', signed=False)
		t += self.CreditCharge.to_bytes(2, byteorder = 'little', signed=False)
		t += self.Status.value.to_bytes(4, byteorder = 'little', signed=False)
		t += self.Command.value.to_bytes(2, byteorder = 'little', signed=False)
		t += self.CreditReq.to_bytes(2, byteorder = 'little', signed=False)
		t += self.Flags.to_bytes(4, byteorder = 'little', signed=False)
		t += self.NextCommand.to_bytes(4, byteorder = 'little', signed=False)
		t += self.MessageId.to_bytes(8, byteorder = 'little', signed=False)
		t += self.Reserved.to_bytes(4, byteorder = 'little', signed=False)
		t += self.TreeId.to_bytes(4, byteorder = 'little', signed=False)
		t += self.SessionId.to_bytes(8, byteorder = 'little', signed=False)
		t += self.Signature
		return t

	def __repr__(self):
		t = '===SMB2 HEADER SYNC===\r\n'
		t += 'ProtocolId:    %s\r\n' % self.ProtocolId
		t += 'StructureSize: %s\r\n' % self.StructureSize
		t += 'CreditCharge:  %s\r\n' % self.CreditCharge
		t += 'Status:    %s\r\n' % self.Status.name
		t += 'Command:   %s\r\n' % self.Command.name
		t += 'CreditReq:    %s\r\n' % self.CreditReq
		t += 'Flags:     %s\r\n' % self.Flags
		t += 'NextCommand: %s\r\n' % self.NextCommand
		t += 'MessageId: %s\r\n' % self.MessageId
		t += 'Reserved:  %s\r\n' % self.Reserved
		t += 'TreeId:    %s\r\n' % self.TreeId
		t += 'SessionId: %s\r\n' % self.SessionId
		t += 'Signature: %s\r\n' % self.Signature
		return t
