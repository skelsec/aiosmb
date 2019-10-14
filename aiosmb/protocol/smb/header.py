import io
import enum

from aiosmb.protocol.smb.command_codes import SMBCommand
from aiosmb.wintypes.ntstatus import NTStatus


class SMBHeaderFlagsEnum(enum.IntFlag):
	SMB_FLAGS_LOCK_AND_READ_OK = 0x01
	SMB_FLAGS_BUF_AVAIL = 0x02
	Reserved = 0x04
	SMB_FLAGS_CASE_INSENSITIVE = 0x08
	SMB_FLAGS_CANONICALIZED_PATHS = 0x10
	SMB_FLAGS_OPLOCK = 0x20
	SMB_FLAGS_OPBATCH = 0x40
	SMB_FLAGS_REPLY = 0x80


class SMBHeaderFlags2Enum(enum.IntFlag):
	SMB_FLAGS2_LONG_NAMES = 0x0001
	SMB_FLAGS2_EAS = 0x0002
	SMB_FLAGS2_SMB_SECURITY_SIGNATURE = 0x0004
	SMB_FLAGS2_IS_LONG_NAME = 0x0040
	SMB_FLAGS2_EXTENDED_SECURITY = 0x0800
	SMB_FLAGS2_DFS = 0x1000
	SMB_FLAGS2_PAGING_IO = 0x2000
	SMB_FLAGS2_NT_STATUS = 0x4000
	SMB_FLAGS2_UNICODE = 0x8000

class SMBHeader:
	def __init__(self):
		self.Protocol = b'\xFFSMB'
		self.Command  = None
		self.Status   = None
		self.Flags    = None
		self.Flags2   = None
		self.PIDHigh  = 0
		self.SecurityFeatures = b'\x00' * 8
		self.Signature = b'\x00' * 8
		self.Reserved = 0
		self.TID      = 65535
		self.PIDLow   = 0
		self.UID      = 0
		self.MessageId      = 0

	@staticmethod
	def from_bytes(bbuff):
		return SMBHeader.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		hdr = SMBHeader()
		hdr.Protocol = buff.read(4)
		assert hdr.Protocol == b'\xFFSMB', "SMBv1 Header Magic incorrect!"
		hdr.Command  = SMBCommand(int.from_bytes(buff.read(1), byteorder='little', signed = False))
		hdr.Status   = NTStatus(int.from_bytes(buff.read(4), byteorder='little', signed = False))
		hdr.Flags    = SMBHeaderFlagsEnum(int.from_bytes(buff.read(1), byteorder='little', signed = False))
		hdr.Flags2   = SMBHeaderFlags2Enum(int.from_bytes(buff.read(2), byteorder='little', signed = False))
		hdr.PIDHigh  = int.from_bytes(buff.read(2), byteorder='little', signed = False)

		if SMBHeaderFlags2Enum.SMB_FLAGS2_SMB_SECURITY_SIGNATURE in hdr.Flags2:
			hdr.SecurityFeatures = buff.read(8)
		else:
			hdr.Signature = buff.read(8)

		hdr.Reserved = int.from_bytes(buff.read(2), byteorder='little', signed = False)
		hdr.TID      = int.from_bytes(buff.read(2), byteorder='little', signed = False)
		hdr.PIDLow   = int.from_bytes(buff.read(2), byteorder='little', signed = False)
		hdr.UID      = int.from_bytes(buff.read(2), byteorder='little', signed = False)
		hdr.MessageId      = int.from_bytes(buff.read(2), byteorder='little', signed = False)
		return hdr

	@staticmethod
	def construct(command, status, flags, flags2, uid = 0, mid = 0, tid = 0, securityfeatures = None, signature = None, pidhigh = 0, pidlow = 0):
		hdr = SMBHeader()
		hdr.Protocol = b'\xFFSMB'
		hdr.Command  = command
		hdr.Status   = status
		hdr.Flags    = flags
		hdr.Flags2   = flags2
		hdr.PIDHigh  = pidhigh

		if SMBHeaderFlags2Enum.SMB_FLAGS2_SMB_SECURITY_SIGNATURE in hdr.Flags2:
			if securityfeatures is None:
				raise Exception('SMB_FLAGS2_SMB_SECURITY_SIGNATURE is present but SecurityFeatures was not supplied!')
			hdr.SecurityFeatures = securityfeatures
		else:
			if signature is not None:
				hdr.Signature = signature

		hdr.Reserved = 0
		hdr.TID      = tid
		hdr.PIDLow   = pidlow
		hdr.UID      = uid
		hdr.MessageId      = mid

		return hdr

	def to_bytes(self):
		t  = self.Protocol
		t += self.Command.value.to_bytes(1, byteorder = 'little', signed=False)
		t += self.Status.value.to_bytes(4, byteorder = 'little', signed=False)
		t += self.Flags.to_bytes(1, byteorder = 'little', signed=False)
		t += self.Flags2.value.to_bytes(2, byteorder = 'little', signed=False)
		t += self.PIDHigh.to_bytes(2, byteorder = 'little', signed=False)
		if self.SecurityFeatures is not None:
			t += self.SecurityFeatures
		elif self.Signature is not None:
			t += self.Signature
		else:
			t += b'\x00'*8
		t += self.Reserved.to_bytes(2, byteorder = 'little', signed=False)
		t += self.TID.to_bytes(2, byteorder = 'little', signed=False)
		t += self.PIDLow.to_bytes(2, byteorder = 'little', signed=False)
		t += self.UID.to_bytes(2, byteorder = 'little', signed=False)
		t += self.MessageId.to_bytes(2, byteorder = 'little', signed=False)
		return t

	def __repr__(self):
		t = '===SMBHeader===\r\n'
		t += 'Command: %s\r\n' % self.Command.name
		t += 'Flags:   %s\r\n' % repr(self.Flags)
		t += 'Flags2:  %s\r\n' % repr(self.Flags2)
		t += 'PIDHigh: %s\r\n' % self.PIDHigh
		t += 'SecurityFeatures: %s\r\n' % (self.SecurityFeatures.hex() if self.SecurityFeatures is not None else 'NONE')
		t += 'Reserved: %s\r\n' % self.Reserved
		t += 'TID: %s\r\n' % self.TID
		t += 'PIDLow: %s\r\n' % self.PIDLow
		t += 'UID: %s\r\n' % self.UID
		t += 'MID: %s\r\n' % self.MessageId
		return t