
from aiosmb.commons.interfaces.file import SMBFile
from aiosmb.commons.access_mask import *
from aiosmb.fscc.FileAttributes import FileAttributes
from aiosmb.fscc.structures.fileinfoclass import FileInfoClass
from aiosmb.protocol.smb2.commands import *
		
class SMBDirectory:
	def __init__(self):
		#self.parent_share = None
		self.tree_id = None #thisdescribes the share itself, not the directory!
		self.fullpath = None
		self.parent_dir = None
		self.name = None
		self.creation_time = None
		self.last_access_time = None
		self.last_write_time = None
		self.change_time = None
		self.allocation_size = None
		self.attributes = None
		self.file_id = None
		self.sid = None
		
		self.files = {}
		self.subdirs = {}

	async def list(self, connection):
		"""
		Lists all files and folders in the directory
		directory: SMBDirectory
		fills the SMBDirectory's data
		"""			
		desired_access = FileAccessMask.FILE_READ_DATA
		share_mode = ShareAccess.FILE_SHARE_READ
		create_options = CreateOptions.FILE_DIRECTORY_FILE | CreateOptions.FILE_SYNCHRONOUS_IO_NONALERT
		file_attrs = 0
		create_disposition = CreateDisposition.FILE_OPEN
		
		try:
			file_id = await connection.create(self.tree_id, self.fullpath, desired_access, share_mode, create_options, create_disposition, file_attrs)
		except Exception as e:
			print(e)
			return
		while True:
			fileinfos = await connection.query_directory(self.tree_id, file_id)
			if not fileinfos:
				break
			for info in fileinfos:
				if info.FileAttributes & FileAttributes.FILE_ATTRIBUTE_DIRECTORY:
					dirname = info.FileName 
					if info.FileName in ['.','..']:
						continue
					subdir = SMBDirectory()
					subdir.tree_id = self.tree_id
					if self.fullpath != '':
						subdir.fullpath = '%s\\%s' % (self.fullpath, info.FileName)
					else:
						subdir.fullpath = info.FileName
					subdir.name = info.FileName
					subdir.creation_time = info.CreationTime
					subdir.last_access_time = info.LastAccessTime
					subdir.last_write_time = info.LastWriteTime
					subdir.change_time = info.ChangeTime
					subdir.allocation_size = info.AllocationSize
					subdir.attributes = info.FileAttributes
					
					self.subdirs[subdir.name] = subdir
					
				else:
					file = SMBFile()
					#file.parent_share = directory.parent_share
					file.tree_id = self.tree_id
					file.parent_dir = None
					if self.fullpath != '':
						file.fullpath = '%s\\%s' % (self.fullpath, info.FileName)
					else:
						file.fullpath = info.FileName
					file.name = info.FileName
					file.size = info.EndOfFile
					file.creation_time = info.CreationTime
					file.last_access_time = info.LastAccessTime
					file.last_write_time = info.LastWriteTime
					file.change_time = info.ChangeTime
					file.allocation_size = info.AllocationSize
					file.attributes = info.FileAttributes		
					self.files[file.name] = file
		
	def __str__(self):
		t = '===== DIRECTORY =====\r\n'
		for k in self.__dict__:
			if k.startswith('parent_'):
				continue
			if isinstance(self.__dict__[k], list):
				for item in self.__dict__[k]:
					t += '%s : %s\r\n' % (k, item)
			elif isinstance(self.__dict__[k], dict):
				for ks in self.__dict__[k]:
					t += '%s : %s\r\n' % (ks, self.__dict__[k][ks])
			else:
				t += '%s : %s\r\n' % (k, self.__dict__[k])
		
		return t