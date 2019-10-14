import io
from aiosmb.wintypes.dtyp.structures.filetime import FILETIME
from aiosmb.wintypes.fscc.FileAttributes import FileAttributes

class FileFullDirectoryInformationList:
	def __init__(self):
		pass
		
	@staticmethod
	def from_bytes(data):
		return FileFullDirectoryInformationList.from_buffer(io.BytesIO(data))
		
	@staticmethod
	def from_buffer(buff):
		pos = buff.tell()
		t = []
		info = FileFullDirectoryInformation.from_buffer(buff)
		t.append(info)
		while info.NextEntryOffset != 0:
			buff.seek(pos + info.NextEntryOffset, 0)
			pos = buff.tell()
			info = FileFullDirectoryInformation.from_buffer(buff)
			t.append(info)
			
		return t
			

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/e8d926d1-3a22-4654-be9c-58317a85540b
class FileFullDirectoryInformation:
	def __init__(self):
		self.NextEntryOffset = None
		self.FileIndex  = None
		self.CreationTime  = None
		self.LastAccessTime  = None
		self.LastWriteTime  = None
		self.ChangeTime  = None
		self.EndOfFile  = None
		self.AllocationSize  = None
		self.FileAttributes   = None
		self.FileNameLength   = None
		self.EaSize   = None
		self.FileName   = None
		
	@staticmethod
	def from_bytes(data):
		return FileFullDirectoryInformation.from_buffer(io.BytesIO(data))
		
	@staticmethod
	def from_buffer(buff):
		msg = FileFullDirectoryInformation()
		msg.NextEntryOffset = int.from_bytes(buff.read(4), byteorder='little', signed = False)
		msg.FileIndex = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		msg.CreationTime = FILETIME.from_buffer(buff).datetime
		msg.LastAccessTime = FILETIME.from_buffer(buff).datetime
		msg.LastWriteTime = FILETIME.from_buffer(buff).datetime
		msg.ChangeTime = FILETIME.from_buffer(buff).datetime
		msg.EndOfFile = int.from_bytes(buff.read(8), byteorder = 'little', signed = True)
		msg.AllocationSize = int.from_bytes(buff.read(8), byteorder = 'little', signed = True)
		msg.FileAttributes = FileAttributes(int.from_bytes(buff.read(4), byteorder = 'little', signed = False))
		msg.FileNameLength = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		msg.EaSize = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		msg.FileName = buff.read(msg.FileNameLength).decode('utf-16-le')
		return msg
		
	def __str__(self):
		t = '===== %s =====\r\n' % 'FileFullDirectoryInformation'
		d = self.__dict__
		for k in d:
			t += '%s : %s\r\n' % (k, d[k])
		return t