
from pathlib import PureWindowsPath
from aiosmb.commons.interfaces.file import SMBFile
from aiosmb.wintypes.access_mask import *
from aiosmb.wintypes.fscc.FileAttributes import FileAttributes
from aiosmb.wintypes.fscc.structures.fileinfoclass import FileInfoClass
from aiosmb.protocol.smb2.commands.query_info import SecurityInfo
from aiosmb.protocol.smb2.commands import *
		
class SMBDirectory:
	def __init__(self):
		#self.parent_share = None
		self.tree_id = None #thisdescribes the share itself, not the directory!
		self.fullpath = None
		self.unc_path = None
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
	
	def get_share_path(self):
		unc = PureWindowsPath(self.unc_path)
		return unc.drive

	async def get_security_descriptor(self, connection):
		if self.sid is None:
			file_id = None
			try:
				desired_access = FileAccessMask.READ_CONTROL
				share_mode = ShareAccess.FILE_SHARE_READ
				create_options = CreateOptions.FILE_DIRECTORY_FILE | CreateOptions.FILE_SYNCHRONOUS_IO_NONALERT
				file_attrs = 0
				create_disposition = CreateDisposition.FILE_OPEN
				file_id = await connection.create(self.tree_id, self.fullpath, desired_access, share_mode, create_options, create_disposition, file_attrs)
				
				self.sid = await connection.query_info(
					self.tree_id, 
					file_id,
					info_type = QueryInfoType.SECURITY, 
					information_class = FileInfoClass.NONE, 
					additional_information = SecurityInfo.ATTRIBUTE_SECURITY_INFORMATION | SecurityInfo.DACL_SECURITY_INFORMATION | SecurityInfo.OWNER_SECURITY_INFORMATION | SecurityInfo.GROUP_SECURITY_INFORMATION, 
					flags = 0, 
				)
			except Exception as e:
				return None, e

			finally:
				if file_id is not None:
					await connection.close(self.tree_id, file_id)


		return self.sid, None
	

	def get_console_output(self):
		lines = []
		for name in self.subdirs:
			directory = self.subdirs[name]
			entry = '%s\t%s\t%s\t%s' % ('drw-rw-rw-',  directory.allocation_size, directory.creation_time, directory.name)
			lines.append(entry)
		for name in self.files:
			directory = self.files[name]
			entry = '%s\t%s\t%s\t%s' % (' rw-rw-rw-',  directory.allocation_size, directory.creation_time, directory.name)
			lines.append(entry)
		return lines
		
	async def create_subdir(self, dir_name, connection):
		try:
			should_close = False #dont close the tree_id only if the directory hasnt been connected to yet
			if not self.tree_id:
				should_close = True
				tree_entry = await connection.tree_connect(self.get_share_path())
				self.tree_id = tree_entry.tree_id

			file_id = None
			newpath = dir_name
			if self.fullpath != '':
				newpath = '%s\\%s' % (self.fullpath, dir_name)
			try:
				file_id = await connection.create(
					self.tree_id, 
					newpath, 
					FileAccessMask.GENERIC_ALL, 
					ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE | ShareAccess.FILE_SHARE_DELETE,
					CreateOptions.FILE_DIRECTORY_FILE | CreateOptions.FILE_SYNCHRONOUS_IO_NONALERT, 
					CreateDisposition.FILE_CREATE, 
					0
				)
				return True, None
			finally:
				if file_id is not None:
					await connection.close(self.tree_id, file_id)
				if should_close is True:       
					await connection.tree_disconnect(self.tree_id)

		except Exception as e:
			return False, e
	
	async def delete_subdir(self, dir_name):
		raise Exception('delete subdir not implemented!')

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
			return False, e
		try:
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
						subdir.unc_path = '%s\\%s' % (self.unc_path, info.FileName)
						subdir.parent_dir = self
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
							file.unc_path = '%s\\%s' % (self.unc_path, info.FileName)
						else:
							file.fullpath = info.FileName
							file.unc_path = '%s\\%s' % (self.unc_path, info.FileName)
						file.name = info.FileName
						file.size = info.EndOfFile
						file.creation_time = info.CreationTime
						file.last_access_time = info.LastAccessTime
						file.last_write_time = info.LastWriteTime
						file.change_time = info.ChangeTime
						file.allocation_size = info.AllocationSize
						file.attributes = info.FileAttributes		
						self.files[file.name] = file
			return True, None
		except Exception as e:
			return False, e
		finally:
			if file_id is not None:
				await connection.close(self.tree_id, file_id)
		
	def __str__(self):
		t = '===== DIRECTORY ===== \r\n'
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