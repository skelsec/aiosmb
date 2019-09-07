
import traceback
import asyncio
from aiosmb.commons.smbcontainer import *
from aiosmb.protocol.smb2.commands import *
from aiosmb.commons.access_mask import *
from aiosmb.fscc.FileAttributes import FileAttributes
from aiosmb.fscc.structures.fileinfoclass import FileInfoClass

class SMBFileSystem:
	def __init__(self, connection):
		self.connection = connection
		
	async def connect_share(self, share):
		"""
		Connect to the share and fills connection related info in the SMBShare object
		"""
		tree_entry = await self.connection.tree_connect(share.fullpath)
		share.tree_id = tree_entry.tree_id
		share.maximal_access = tree_entry.maximal_access
		init_dir = SMBDirectory()
		init_dir.parent_share = share
		init_dir.fullpath = ''
		share.subdirs[''] = init_dir
		
		return

	async def list_directory(self, directory):
		"""
		Lists all files and folders in the directory
		directory: SMBDirectory
		fills the SMBDirectory's data
		"""
		if not directory.parent_share.tree_id:
			await self.connect_share(directory.parent_share)
			
		desired_access = FileAccessMask.FILE_READ_DATA
		share_mode = ShareAccess.FILE_SHARE_READ
		create_options = CreateOptions.FILE_DIRECTORY_FILE | CreateOptions.FILE_SYNCHRONOUS_IO_NONALERT
		file_attrs = 0
		create_disposition = CreateDisposition.FILE_OPEN
		
		try:
			file_id = await self.connection.create(directory.parent_share.tree_id, directory.fullpath, desired_access, share_mode, create_options, create_disposition, file_attrs)
		except Exception as e:
			print(e)
			return
		while True:
			fileinfos = await self.connection.query_directory(directory.parent_share.tree_id, file_id)
			if not fileinfos:
				break
			for info in fileinfos:
				if info.FileAttributes & FileAttributes.FILE_ATTRIBUTE_DIRECTORY:
					dirname = info.FileName 
					if info.FileName in ['.','..']:
						continue
					subdir = SMBDirectory()
					subdir.parent_share = directory.parent_share
					if directory.fullpath != '':
						subdir.fullpath = '%s\\%s' % (directory.fullpath, info.FileName)
					else:
						subdir.fullpath = info.FileName
					subdir.name = info.FileName
					subdir.creation_time = info.CreationTime
					subdir.last_access_time = info.LastAccessTime
					subdir.last_write_time = info.LastWriteTime
					subdir.change_time = info.ChangeTime
					subdir.allocation_size = info.AllocationSize
					subdir.attributes = info.FileAttributes
					
					directory.subdirs[subdir.name] = subdir
					
				else:
					file = SMBFile()
					file.parent_share = directory.parent_share
					file.parent_dir = None
					if directory.fullpath != '':
						file.fullpath = '%s\\%s' % (directory.fullpath, info.FileName)
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
					directory.files[file.name] = file
		
		
	def get_file(self, file, destination_path):
		"""
		Downloads the file to the given destination path
		file: SMBFile
		"""
		pass
		
	async def get_sid(self, dof):
		"""
		Gets the file's SID and fills the file object's attribute
		file: SMBFile
		"""
		if not dof.file_id:
			try:
				await self.get_fileid(dof)
			except Exception as e:
				return
		
		res = await self.connection.query_info(dof.parent_share.tree_id, dof.file_id, info_type = QueryInfoType.SECURITY, information_class = FileInfoClass.NONE, additional_information = SecurityInfo.OWNER_SECURITY_INFORMATION | SecurityInfo.GROUP_SECURITY_INFORMATION | SecurityInfo.DACL_SECURITY_INFORMATION)
		if res:
			dof.sid = res
			
	async def get_fileid(self, dof):
		"""
		Gets a fileID to the destination file or directory. It is needed for performing SMB operations on the file/dir
		dof: SMBFile or SMBDirectory
		"""
		if not dof.parent_share.tree_id:
			await self.connect_share(dof.parent_share)
		
		desired_access = FileAccessMask.GENERIC_READ
		share_mode = ShareAccess.FILE_SHARE_READ
		create_options = CreateOptions.FILE_NON_DIRECTORY_FILE if isinstance(dof, SMBFile) else CreateOptions.FILE_DIRECTORY_FILE
		create_options |= CreateOptions.FILE_SYNCHRONOUS_IO_NONALERT
		file_attrs = 0
		create_disposition = CreateDisposition.FILE_OPEN
		
		file_id = await self.connection.create(dof.parent_share.tree_id, dof.fullpath, desired_access, share_mode, create_options, create_disposition, file_attrs)
		dof.file_id = file_id
		
	def create_file(self, file):
		"""
		Creates a new file on the remote endpoint
		"""
		pass
		
	def write_file(self, file, offset, data):
		"""
		Writes the given data to the given offset to the file
		file: SMBFile
		offset: int
		data: io.BytesIO buffer
		"""
		pass
		
	async def quit(self):
		self.connection.terminate()
		
	async def enumerate_directory_stack(self, directory, maxdepth = 4, with_sid = False, exclude_dirs = ['Windows','Program Files','Program Files (x86)']):
		dirs = [(directory, maxdepth)]
		
		while len(dirs) != 0:
			directory, md = dirs.pop()
			if directory.name in exclude_dirs:
				continue
			await self.list_directory(directory)
			await asyncio.sleep(0) #give other tasks a chance...
			if with_sid == True:
				for file_name in directory.files:
					await self.get_sid(directory.files[file_name])
				for directory_name in directory.subdirs:
					await self.get_sid(directory.subdirs[directory_name])
			
			await self.close_directory(directory)		
			yield directory			
			if md > maxdepth:
				continue
			
			for directory_name in directory.subdirs:
				dirs.append((directory.subdirs[directory_name], md - 1))
		
	async def enumerate_directory(self, directory, maxdepth = 4, with_sid = False):
		await self.list_directory(directory)
		await asyncio.sleep(0) #give other tasks a chance...
		
		if with_sid == True:
			for file_name in directory.files:
				await self.get_sid(directory.files[file_name])
			for directory_name in directory.subdirs:
				await self.get_sid(directory.subdirs[directory_name])
		
		if max_depth == 0:
			return
		
		for directory_name in directory.subdirs:
			await self.enumerate_directory(directory.subdirs[directory_name], maxdepth = maxdepth -1, with_sid = with_sid)
		
	async def enumerate_share(self, share, maxdepth = 4, with_sid = False):
		try:
			await self.connect_share(share)
		except Exception as e:
			return
		
		await self.list_share(share)
		
		for directory_name in share.subdirs:
			await self.enumerate_directory(share.subdirs[directory_name], maxdepth = maxdepth, with_sid = with_sid)
			
	def print_tree(self, share):
		print(str(share))
		
		
	async def close_directory(self, directory):
		if directory.parent_share is None or directory.parent_share.tree_id is None:
			return
		for file_name in directory.files:
			if directory.files[file_name].file_id is None:
				continue
			
			try:
				await self.connection.close(directory.parent_share.tree_id, directory.files[file_name].file_id)
			except Exception as e:
				pass
		
		if directory.file_id is None:
			return
		try:
			await self.connection.close(directory.parent_share.tree_id, directory.file_id)
		except Exception as e:
			pass

