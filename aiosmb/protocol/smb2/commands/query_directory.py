import io
import enum

from aiosmb.wintypes.fscc.structures.fileinfoclass import *

class QueryDirectoryFlag(enum.IntFlag):
	SMB2_RESTART_SCANS = 0x01 #The server MUST restart the enumeration from the beginning as specified in section 3.3.5.18.
	SMB2_RETURN_SINGLE_ENTRY = 0x02 #The server MUST only return the first entry of the search results.
	SMB2_INDEX_SPECIFIED = 0x04 #The server SHOULD<64> return entries beginning at the byte number specified by FileIndex.
	SMB2_REOPEN = 0x10 #The server MUST restart the enumeration from the beginning, and the search pattern MUST be changed to the provided value.

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/10906442-294c-46d3-8515-c277efe1f752
class QUERY_DIRECTORY_REQ:
	def __init__(self):
		self.StructureSize = 33
		self.FileInformationClass  = None
		self.Flags  = None
		self.FileIndex  = None
		self.FileId  = None
		self.FileNameOffset  = 0
		self.FileNameLength  = 0
		self.OutputBufferLength  = 65535
		
		self.Buffer = None
		
		#high-level param
		self.FileName = None #this is actually a search pattern, but referred to as filename
		
	def to_bytes(self):
		if self.FileName:
			self.Buffer = self.FileName.encode('utf-16-le')
			self.FileNameOffset = 64 + 2+1+1+4+16+2+2+4
			self.FileNameLength = len(self.Buffer)
			
		t  = self.StructureSize.to_bytes(2, byteorder='little', signed = False)
		t += self.FileInformationClass.value.to_bytes(1, byteorder='little', signed = False)
		t += self.Flags.to_bytes(1, byteorder='little', signed = False)
		t += self.FileIndex.to_bytes(4, byteorder='little', signed = False)
		t += self.FileId.to_bytes(16, byteorder='little', signed = False)
		t += self.FileNameOffset.to_bytes(2, byteorder='little', signed = False)
		t += self.FileNameLength.to_bytes(2, byteorder='little', signed = False)
		t += self.OutputBufferLength.to_bytes(4, byteorder='little', signed = False)
		
		if self.Buffer:
			t += self.Buffer
		return t

	@staticmethod
	def from_bytes(bbuff):
		return QUERY_DIRECTORY_REQ.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		msg = QUERY_DIRECTORY_REQ()
		msg.StructureSize   = int.from_bytes(buff.read(2), byteorder='little')
		assert msg.StructureSize == 33
		msg.FileInformationClass  = FileInformationClass(int.from_bytes(buff.read(1), byteorder='little'))
		msg.Flags   = QueryDirectoryFlag(int.from_bytes(buff.read(1), byteorder='little'))
		msg.FileIndex    = int.from_bytes(buff.read(4), byteorder = 'little')
		msg.FileId    = int.from_bytes(buff.read(16), byteorder = 'little')
		msg.FileNameOffset = int.from_bytes(buff.read(2), byteorder = 'little')
		msg.FileNameLength = int.from_bytes(buff.read(2), byteorder = 'little')
		msg.OutputBufferLength = int.from_bytes(buff.read(4), byteorder = 'little')

		if msg.FileNameLength > 0:
			buff.seek(msg.FileNameOffset, io.SEEK_SET)
			msg.FileName = buff.read(msg.FileNameLength).deocde('utf-16-le')

		return msg

	def __repr__(self):
		t = '==== SMB2 QUERY DIRECTORY REQ ====\r\n'
		t += 'StructureSize: %s\r\n' % self.StructureSize
		t += 'FileInformationClass: %s\r\n' % self.FileInformationClass
		t += 'Flags: %s\r\n' % self.Flags
		t += 'FileIndex: %s\r\n' % self.FileIndex
		t += 'FileId: %s\r\n' % self.FileId
		t += 'FileNameOffset: %s\r\n' % self.FileNameOffset
		t += 'FileNameLength: %s\r\n' % self.FileNameLength
		t += 'OutputBufferLength: %s\r\n' % self.OutputBufferLength
		t += 'FileName: %s\r\n' % self.FileName
		return t
		
		
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/4f75351b-048c-4a0c-9ea3-addd55a71956
class QUERY_DIRECTORY_REPLY:
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
		return QUERY_DIRECTORY_REPLY.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		msg = QUERY_DIRECTORY_REPLY()
		msg.StructureSize   = int.from_bytes(buff.read(2), byteorder='little')
		assert msg.StructureSize == 9
		msg.OutputBufferOffset  = int.from_bytes(buff.read(2), byteorder='little')
		msg.OutputBufferLength  = int.from_bytes(buff.read(4), byteorder='little')
		
		if msg.OutputBufferLength > 0:
			buff.seek(msg.OutputBufferOffset, io.SEEK_SET)
			msg.Data= buff.read(msg.OutputBufferLength)

		return msg

	def __repr__(self):
		t = '==== SMB2 QUERY INFO REQ ====\r\n'
		t += 'StructureSize: %s\r\n' % self.StructureSize
		t += 'OutputBufferOffset: %s\r\n' % self.OutputBufferOffset
		t += 'OutputBufferLength: %s\r\n' % self.OutputBufferLength
		t += 'Data: %s\r\n' % self.Data
		return t