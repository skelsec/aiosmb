from aiosmb.commons.smbcontainer import *
from aiosmb.protocol.smb2.commands import *
from aiosmb.commons.access_mask import *

class SMBEndpoint:
	def __init__(self):
		self.address = None		
		self.shares = {}
		self.connection = None
		
	async def list_shares(self):
		"""
		Returns a list of SMBShare objects
		"""
		raise Exception('Not implemented :(')
		
	async def connect_share(self, share):
		"""
		Connect to the share and fills connection related info in the SMBShare object
		"""
		tree_entry = await self.connection.tree_connect(share.fullpath)
		share.tree_id = tree_entry.tree_id
		share.maximal_access = tree_entry.maximal_access
		
		return
		
	async def list_share(self, share):
		"""
		Lists all files and folders on a share, adds the info to the share object
		
		"""
		if not share.tree_id:
			await self.connect_share(share)
		
		file_path = ''
		desired_access = FileAccessMask.FILE_READ_DATA | FileAccessMask.FILE_READ_ATTRIBUTES
		share_mode = ShareAccess.FILE_SHARE_READ
		create_options = CreateOptions.FILE_DIRECTORY_FILE | CreateOptions.FILE_SYNCHRONOUS_IO_NONALERT 
		file_attrs = 0
		create_disposition = CreateDisposition.FILE_OPEN
		
		file_id = await self.connection.create(share.tree_id, file_path, desired_access, share_mode, create_options, create_disposition, file_attrs)
		while True:
			fileinfos = await self.connection.query_directory(share.tree_id, file_id)
			if not fileinfos:
				break
			
			for info in fileinfos:
				if info.FileAttributes & FileAttributes.FILE_ATTRIBUTE_DIRECTORY:
					dirname = info.FileName 
					if info.FileName in ['.','..']:
						continue
					
					directory = SMBDirectory()
					directory.parent_share = share
					directory.fullpath = dirname
					directory.name = info.FileName
					directory.creation_time = info.CreationTime
					directory.last_access_time = info.LastAccessTime
					directory.last_write_time = info.LastWriteTime
					directory.change_time = info.ChangeTime
					directory.allocation_size = info.AllocationSize
					directory.attributes = info.FileAttributes
					share.subdirs[directory.name] = directory
					
				else:
					file = SMBFile()
					file.parent_share = share
					file.parent_dir = None
					file.fullpath = info.FileName
					file.name = info.FileName
					file.size = info.EndOfFile
					file.creation_time = info.CreationTime
					file.last_access_time = info.LastAccessTime
					file.last_write_time = info.LastWriteTime
					file.change_time = info.ChangeTime
					file.allocation_size = info.AllocationSize
					file.attributes = info.FileAttributes		
					share.files[file.name] = file
		
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
		create_options = CreateOptions.FILE_DIRECTORY_FILE
		file_attrs = 0
		create_disposition = CreateDisposition.FILE_OPEN
		
		file_id = await self.connection.create(directory.parent_share.tree_id, directory.fullpath, desired_access, share_mode, create_options, create_disposition, file_attrs)
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
			await self.get_fileid(dof)
		res = await self.connection.query_info(dof.parent_share.tree_id, dof.file_id, info_type = QueryInfoType.SECURITY, info_class = FileInfoClass.NONE, additional_information = SecurityInfo.OWNER_SECURITY_INFORMATION | SecurityInfo.GROUP_SECURITY_INFORMATION | SecurityInfo.DACL_SECURITY_INFORMATION)
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
		
	async def enumerate_directory(self, directory):
		await self.list_directory(directory)
		
		for directory_name in directory.subdirs:
			await self.enumerate_directory(directory.subdirs[directory_name])
		
	async def enumerate_share(self, share):
		await self.connect_share(share)
		await self.list_share(share)
		for directory_name in share.subdirs:
			await self.enumerate_directory(share.subdirs[directory_name])
			
	async def enumerate_sids(self, share):
		for file_name in share.files:
			await self.get_sid(share.files[file_name])
		for directory_name in share.subdirs:
			await self.get_sid(share.subdirs[directory_name])
		for directory_name in share.subdirs:
			await self.enumerate_sids(share.subdirs[directory_name])
		
	async def test(self):
		share = SMBShare()
		share.fullpath = '\\\\10.10.10.2\\Users'
		share.name = 'Users'
		self.shares[share.name] = share
		
		await self.enumerate_share(share)
		
		print('=====================================================')
		self.print_tree(share)
		input('a')
		await self.enumerate_sids(share)
		
	def print_tree(self, share):
		print(str(share))


"""
class SMBFileOps:
	def __init__(self):
		self.connection = None
		
	def list_directory(self, path, recursive = False):
	
	
	def get_file_dacl(self, path):

"""	