import io
import enum
import sys

from aiosmb.protocol.smb.commands import *
from aiosmb.protocol.smb.header import *

# https://msdn.microsoft.com/en-us/library/ee441774.aspx
class SMBMessage:
	"""
	Base class for all SMB version 1 messages
	"""
	def __init__(self, header = None, command = None):
		self.header  = header #https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/69a29f73-de0c-45a6-a1aa-8ceeea42217f
		self.command = command

	@staticmethod
	def from_bytes(bbuff):
		return SMBMessage.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		msg = SMBMessage()
		msg.header = SMBHeader.from_buffer(buff)
		classname = msg.header.Command.name
		if SMBHeaderFlagsEnum.SMB_FLAGS_REPLY in msg.header.Flags:
			classname += '_REPLY'
		else:
			classname += '_REQ'
		class_ = getattr(sys.modules[__name__], classname)
		msg.command = class_.from_buffer(buff)
		
		return msg

	def to_bytes(self):
		t  = self.header.to_bytes()
		t += self.command.to_bytes() 
		return t

	def __repr__(self):
		t = '== SMBMessage ==\r\n'
		t += repr(self.header)
		t += repr(self.command)
		return t

