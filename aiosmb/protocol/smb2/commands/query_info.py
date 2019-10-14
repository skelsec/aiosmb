import io
import enum

from aiosmb.wintypes.fscc.structures.fileinfoclass import *
	
class QueryInfoType(enum.Enum):
	FILE = 0x01 #The file information is requested.
	FILESYSTEM = 0x02 #The underlying object store information is requested.
	SECURITY = 0x03 #The security information is requested.
	QUOTA = 0x04
	
class SecurityInfo(enum.IntFlag):
	OWNER_SECURITY_INFORMATION = 0x00000001 #The client is querying the owner from the security descriptor of the file or named pipe.
	GROUP_SECURITY_INFORMATION = 0x00000002 #The client is querying the group from the security descriptor of the file or named pipe.
	DACL_SECURITY_INFORMATION = 0x00000004 #The client is querying the discretionary access control list from the security descriptor of the file or named pipe.
	SACL_SECURITY_INFORMATION = 0x00000008 #The client is querying the system access control list from the security descriptor of the file or named pipe.
	LABEL_SECURITY_INFORMATION = 0x00000010 #The client is querying the integrity label from the security descriptor of the file or named pipe.
	ATTRIBUTE_SECURITY_INFORMATION = 0x00000020 #The client is querying the resource attribute from the security descriptor of the file or named pipe.
	SCOPE_SECURITY_INFORMATION = 0x00000040 #The client is querying the central access policy of the resource from the security descriptor of the file or named pipe.
	BACKUP_SECURITY_INFORMATION = 0x00010000 #The client is querying the security descriptor information used for backup operation.
	
class EaInformation(enum.IntFlag):
	SL_RESTART_SCAN = 0x00000001 #Restart the scan for EAs from the beginning.
	SL_RETURN_SINGLE_ENTRY = 0x00000002 #Return a single EA entry in the response buffer.
	SL_INDEX_SPECIFIED = 0x00000004 #The caller has specified an EA index.

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/d623b2f7-a5cd-4639-8cc9-71fa7d9f9ba9
class QUERY_INFO_REQ:
	def __init__(self):
		self.StructureSize = 41
		self.InfoType = None
		self.FileInfoClass = None
		self.OutputBufferLength = 65535
		self.InputBufferOffset = 0
		self.Reserved = 0
		self.InputBufferLength = 0
		self.AdditionalInformation = None
		self.Flags = None
		self.FileId = None
		self.Buffer = None
		
		#high-level param
		self.Data = None
		
	def to_bytes(self):
		if self.Data:
			self.Buffer = io.BytesIO(self.Data)
			self.InputBufferOffset = 64 + 2+1+1+4+2+2+2+4+4+16
			self.InputBufferLength = len(self.Data)
			
		t  = self.StructureSize.to_bytes(2, byteorder='little', signed = False)
		t += self.InfoType.value.to_bytes(1, byteorder='little', signed = False)
		t += self.FileInfoClass.value.to_bytes(1, byteorder='little', signed = False)
		t += self.OutputBufferLength.to_bytes(4, byteorder='little', signed = False)
		t += self.InputBufferOffset.to_bytes(2, byteorder='little', signed = False)
		t += self.Reserved.to_bytes(2, byteorder='little', signed = False)
		t += self.InputBufferLength.to_bytes(4, byteorder='little', signed = False)
		t += self.AdditionalInformation.to_bytes(4, byteorder='little', signed = False)
		t += self.Flags.to_bytes(4, byteorder='little', signed = False)
		t += self.FileId.to_bytes(16, byteorder='little', signed = False)
		
		if self.Buffer:
			t += self.Buffer
		return t

	@staticmethod
	def from_bytes(bbuff):
		return QUERY_INFO_REQ.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		msg = QUERY_INFO_REQ()
		msg.StructureSize   = int.from_bytes(buff.read(2), byteorder='little')
		assert msg.StructureSize == 41
		msg.InfoType = QueryInfoType(int.from_bytes(buff.read(1), byteorder='little'))
		msg.FileInfoClass  = FileInfoClass(int.from_bytes(buff.read(1), byteorder='little'))
		msg.OutputBufferLength  = int.from_bytes(buff.read(4), byteorder = 'little')
		msg.InputBufferOffset  = int.from_bytes(buff.read(2), byteorder = 'little')
		msg.Reserved   = int.from_bytes(buff.read(2), byteorder = 'little')
		msg.InputBufferLength    = int.from_bytes(buff.read(2), byteorder = 'little')
		msg.AdditionalInformation = SecurityInfo(int.from_bytes(buff.read(4), byteorder = 'little'))
		msg.Flags = EaInformation(int.from_bytes(buff.read(4), byteorder = 'little'))
		msg.FileId = int.from_bytes(buff.read(16), byteorder = 'little')

		if msg.InputBufferLength > 0:
			buff.seek(msg.InputBufferOffset, io.SEEK_SET)
			msg.Buffer= buff.read(msg.InputBufferLength)

		return msg

	def __repr__(self):
		t = '==== SMB2 QUERY INFO REQ ====\r\n'
		t += 'StructureSize: %s\r\n' % self.StructureSize
		t += 'InfoType: %s\r\n' % self.InfoType
		t += 'FileInfoClass: %s\r\n' % self.FileInfoClass
		t += 'OutputBufferLength: %s\r\n' % self.OutputBufferLength
		t += 'InputBufferOffset: %s\r\n' % self.InputBufferOffset
		t += 'InputBufferLength: %s\r\n' % self.InputBufferLength
		t += 'AdditionalInformation: %s\r\n' % self.AdditionalInformation
		t += 'Flags: %s\r\n' % self.Flags
		t += 'FileId: %s\r\n' % self.FileId
		t += 'Buffer: %s\r\n' % self.Buffer
		return t
		
		
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/3b1b3598-a898-44ca-bfac-2dcae065247f
class QUERY_INFO_REPLY:
	def __init__(self):
		self.StructureSize = 9
		self.OutputBufferOffset  = None
		self.OutputBufferLength  = None
		self.Buffer = None
		
		#high-level param
		self.Data = None
		
	def to_bytes(self):
		pass

	@staticmethod
	def from_bytes(bbuff):
		return QUERY_INFO_REPLY.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		msg = QUERY_INFO_REPLY()
		msg.StructureSize   = int.from_bytes(buff.read(2), byteorder='little')
		assert msg.StructureSize == 9
		msg.OutputBufferOffset  = int.from_bytes(buff.read(2), byteorder='little')
		msg.OutputBufferLength  = int.from_bytes(buff.read(4), byteorder='little')
		

		if msg.OutputBufferLength > 0:
			buff.seek(msg.OutputBufferOffset, io.SEEK_SET)
			msg.Data = buff.read(msg.OutputBufferLength)

		return msg

	def __repr__(self):
		t = '==== SMB2 QUERY INFO REQ ====\r\n'
		t += 'StructureSize: %s\r\n' % self.StructureSize
		t += 'OutputBufferOffset: %s\r\n' % self.OutputBufferOffset
		t += 'OutputBufferLength: %s\r\n' % self.OutputBufferLength
		t += 'Buffer: %s\r\n' % self.Buffer
		return t