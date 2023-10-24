from typing import Dict, List
import asyncio
import datetime
from contextlib import asynccontextmanager
from pathlib import PureWindowsPath

from aiosmb.commons.interfaces.file import SMBFile
from aiosmb.wintypes.access_mask import *
from aiosmb.wintypes.fscc.FileAttributes import FileAttributes
from aiosmb.wintypes.fscc.structures.fileinfoclass import FileInfoClass
from aiosmb.protocol.smb2.commands.query_info import SecurityInfo
from aiosmb.protocol.smb2.commands import *


from aiosmb.connection import SMBConnection
from aiosmb.commons.connection.target import SMBTarget

class SMBDirectory:
	def __init__(self):
		#self.parent_share = None
		self.tree_id:int = None #thisdescribes the share itself, not the directory!
		self.fullpath:str = None
		self.unc_path:str = None
		self.parent_dir = None
		self.name:str = None
		self.creation_time:datetime.datetime = None
		self.last_access_time:datetime.datetime = None
		self.last_write_time:datetime.datetime = None
		self.change_time:datetime.datetime = None
		self.allocation_size:datetime.datetime = None
		self.attributes:FileAttributes = None
		self.file_id:int = None
		self.security_descriptor = None
		
		self.files:Dict[str, SMBFile] = {}
		self.subdirs:Dict[str, SMBDirectory] = {}

	@staticmethod
	def from_uncpath(unc_path:str):
		"""
		Creates SMBFile object from the UNC path supplied.
		Example uncpath: \\\\127.0.0.1\\C$\\temp\\test.exe
		"""
		unc = PureWindowsPath(unc_path)
		f = SMBDirectory()
		f.share_path = unc.drive
		f.fullpath = '\\'.join(unc.parts[1:])
		f.unc_path = unc_path
		
		return f
	
	@staticmethod
	def from_smbtarget(target:SMBTarget):
		"""
		Creates SMBDirectory object from the SMBUrl object
		"""
		if target.path is None:
			return None
		
		fpath = target.path.replace('/','\\')
		temp = '\\\\%s%s'
		unc = temp % (target.get_hostname_or_ip(), fpath)
		return SMBDirectory.from_uncpath(unc)

	@staticmethod
	def from_remotepath(connection:SMBConnection, remotepath:str):
		"""
		Creates SMBFile object from the connection and the remote path supplied.
		Example remotepath: \\C$\\temp\\test.exe
		"""
		temp = '\\\\%s\\%s'
		if remotepath[0] == '\\':
			temp = '\\\\%s%s'
		unc = temp % (connection.target.get_hostname_or_ip(), remotepath)
		return SMBDirectory.from_uncpath(unc)

	@staticmethod
	async def delete_unc(connection:SMBConnection, remotepath:str):
		"""
		Deletes a directory at a given path.
		"""
		try:
			remfile = SMBDirectory.from_uncpath(remotepath)
			tree_entry, err = await connection.tree_connect(remfile.share_path)
			if err is not None:
				raise err
			tree_id = tree_entry.tree_id

			desired_access = FileAccessMask.DELETE | FileAccessMask.FILE_READ_ATTRIBUTES
			share_mode = ShareAccess.FILE_SHARE_DELETE
			create_options = CreateOptions.FILE_DIRECTORY_FILE | CreateOptions.FILE_DELETE_ON_CLOSE 
			create_disposition = CreateDisposition.FILE_OPEN
			file_attrs = 0

			file_id, err = await connection.create(tree_id, remfile.fullpath, desired_access, share_mode, create_options, create_disposition, file_attrs, return_reply = False)
			if err is not None:
				raise err
			if file_id is not None:
				await connection.close(tree_id, file_id)

			await connection.tree_disconnect(tree_id)
			return True, None
		
		except Exception as e:
			return False, e

	@staticmethod
	async def create_remote(connection:SMBConnection, remotepath:str):
		try:
			remfile = SMBDirectory.from_remotepath(connection, remotepath)
			tree_entry, err = await connection.tree_connect(remfile.share_path)
			if err is not None:
				raise err
			tree_id = tree_entry.tree_id

			desired_access = FileAccessMask.FILE_READ_DATA | FileAccessMask.FILE_WRITE_DATA | FileAccessMask.FILE_READ_EA | FileAccessMask.FILE_WRITE_EA | FileAccessMask.FILE_READ_ATTRIBUTES | FileAccessMask.FILE_WRITE_ATTRIBUTES | FileAccessMask.READ_CONTROL | FileAccessMask.DELETE | FileAccessMask.SYNCHRONIZE
			share_mode = ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE | ShareAccess.FILE_SHARE_DELETE
			create_options = CreateOptions.FILE_DIRECTORY_FILE | CreateOptions.FILE_SYNCHRONOUS_IO_NONALERT
			create_disposition = CreateDisposition.FILE_CREATE
			file_attrs = 0

			file_id, err = await connection.create(tree_id, remfile.fullpath, desired_access, share_mode, create_options, create_disposition, file_attrs, return_reply = False)
			if err is not None:
				raise err
			if file_id is not None:
				await connection.close(tree_id, file_id)

			await connection.tree_disconnect(tree_id)
			return True, None

		except Exception as e:
			return False, e

	def get_share_path(self):
		unc = PureWindowsPath(self.unc_path)
		return unc.drive

	def get_subdir_paths(self, fullpath:bool = False):
		"""
		Returns a list of paths of all subdirectories in the directory
		"""
		paths = []
		for f in self.subdirs.values():
			if fullpath is True:
				paths.append(f.unc_path)
			else:
				paths.append(f.fullpath)
		return paths

	def get_file_paths(self, fullpath:bool = False):
		"""
		Returns a list of paths of all files in the directory
		"""
		paths = []
		for f in self.files.values():
			if fullpath is True:
				paths.append(f.unc_path)
			else:
				paths.append(f.fullpath)
		return paths

	async def delete(self, connection:SMBConnection):
		try:
			if self.file_id is not None:
				# if the directory is open, first we need to close it
				await connection.close(self.tree_id, self.file_id)
			return await SMBDirectory.delete_unc(connection, self.unc_path)
		except Exception as e:
			return False, e

	async def get_security_descriptor(self, connection:SMBConnection):
		if self.security_descriptor is None:
			file_id = None
			try:
				tree_id = self.tree_id
				if self.tree_id is None:
					tree_entry, err = await connection.tree_connect(self.share_path)
					if err is not None:
						raise err
					tree_id = tree_entry.tree_id

				desired_access = FileAccessMask.READ_CONTROL
				share_mode = ShareAccess.FILE_SHARE_READ
				create_options = CreateOptions.FILE_DIRECTORY_FILE | CreateOptions.FILE_SYNCHRONOUS_IO_NONALERT
				file_attrs = 0
				create_disposition = CreateDisposition.FILE_OPEN
				file_id, err = await connection.create(tree_id, self.fullpath, desired_access, share_mode, create_options, create_disposition, file_attrs)
				if err is not None:
					raise err
				
				self.security_descriptor, err = await connection.query_info(
					tree_id, 
					file_id,
					info_type = QueryInfoType.SECURITY, 
					information_class = FileInfoClass.NONE, 
					additional_information = SecurityInfo.ATTRIBUTE_SECURITY_INFORMATION | SecurityInfo.DACL_SECURITY_INFORMATION | SecurityInfo.OWNER_SECURITY_INFORMATION | SecurityInfo.GROUP_SECURITY_INFORMATION, 
					flags = 0, 
				)
				if err is not None:
					raise err
			except Exception as e:
				return None, e

			finally:
				if file_id is not None:
					await connection.close(tree_id, file_id)
				if tree_id is not None and self.tree_id is None:
					await connection.tree_disconnect(tree_id)


		return self.security_descriptor, None
	

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
		
	async def create_subdir(self, dir_name:str, connection:SMBConnection):
		try:
			should_close = False #dont close the tree_id only if the directory hasnt been connected to yet
			if not self.tree_id:
				should_close = True
				tree_entry, err = await connection.tree_connect(self.get_share_path())
				if err is not None:
					raise err
				self.tree_id = tree_entry.tree_id

			file_id = None
			newpath = dir_name
			if self.fullpath != '':
				newpath = '%s\\%s' % (self.fullpath, dir_name)
			try:
				file_id, err = await connection.create(
					self.tree_id, 
					newpath, 
					FileAccessMask.FILE_READ_DATA | FileAccessMask.FILE_WRITE_DATA | FileAccessMask.FILE_READ_EA | FileAccessMask.FILE_WRITE_EA | FileAccessMask.FILE_READ_ATTRIBUTES | FileAccessMask.FILE_WRITE_ATTRIBUTES | FileAccessMask.READ_CONTROL | FileAccessMask.DELETE | FileAccessMask.SYNCHRONIZE, 
					ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE | ShareAccess.FILE_SHARE_DELETE,
					CreateOptions.FILE_DIRECTORY_FILE | CreateOptions.FILE_SYNCHRONOUS_IO_NONALERT, 
					CreateDisposition.FILE_CREATE, 
					0
				)
				if err is not None:
					raise err
				return True, None
			finally:
				if file_id is not None:
					await connection.close(self.tree_id, file_id)
				if should_close is True:       
					await connection.tree_disconnect(self.tree_id)

		except Exception as e:
			return False, e
	
	async def delete_subdir(self, dir_name:str):
		raise Exception('delete subdir not implemented!')

	async def list_r(self, connection:SMBConnection, depth:int = 3, maxentries:int = None, fetch_dir_sd:bool = False, fetch_file_sd:bool = False, exclude_dir:List[str] = [], filter_cb=None):
		"""
		recursive list files and folders
		Beware this will clear out the lists of files/folders to save memory!
		"""
		if depth == 0:
			return
		depth -= 1
		ctr = 0

		try:
			async for obj, otype, err in self.list_gen(connection):
				await asyncio.sleep(0)
				if otype == 'dir' and fetch_dir_sd is True and obj.name not in exclude_dir:
					obj.tree_id = self.tree_id
					_, err = await obj.get_security_descriptor(connection)
					#if err is not None:
					#	print(err)
				
				if otype == 'file' and fetch_file_sd is True:
					obj.tree_id = self.tree_id
					_, err = await obj.get_security_descriptor(connection)
					#if err is not None:
					#	print(err)

				yield obj, otype, err
				
				ctr += 1
				if err is not None:
					break
				
				if ctr == maxentries:
					yield self, 'maxed', None
					break
				
				if otype == 'dir' and obj.name not in exclude_dir:
					if filter_cb is not None:
						res = await filter_cb('dir', obj)
						if res is False:
							continue
					obj.tree_id = self.tree_id
					async for e,t,err in obj.list_r(
							connection, 
							depth, 
							maxentries = maxentries, 
							exclude_dir = exclude_dir,
							fetch_dir_sd = fetch_dir_sd, 
							fetch_file_sd = fetch_file_sd,
							filter_cb = filter_cb):
						yield e,t,err
						# await asyncio.sleep(0)
		except Exception as e:
			yield None, None, e


	async def list_gen(self, connection:SMBConnection):
		"""
		Lists all files and folders in the directory, yields the results as they arrive
		directory: SMBDirectory
		DOESN'T fill the SMBDirectory's data
		"""
		self.files = {}
		self.subdirs = {}
		
		desired_access = FileAccessMask.FILE_READ_DATA
		share_mode = ShareAccess.FILE_SHARE_READ
		create_options = CreateOptions.FILE_DIRECTORY_FILE | CreateOptions.FILE_SYNCHRONOUS_IO_NONALERT
		file_attrs = 0
		create_disposition = CreateDisposition.FILE_OPEN

	
		if not self.tree_id:
			tree_entry, err = await connection.tree_connect(self.get_share_path())
			if err is not None:
				yield self, 'dir', err
				return
			self.tree_id = tree_entry.tree_id
		
		file_id, err = await connection.create(self.tree_id, self.fullpath, desired_access, share_mode, create_options, create_disposition, file_attrs)
		if err is not None:
			yield self, 'dir', err
			return
		try:
			while True:
				await asyncio.sleep(0)
				fileinfos, err = await connection.query_directory(self.tree_id, file_id)
				if err is not None:
					raise err
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
						
						yield subdir, 'dir', None
						
					else:
						file = SMBFile()
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
						yield file, 'file', None
			
		except Exception as e:
			yield self, 'dir', e
			return
		finally:
			if file_id is not None:
				await connection.close(self.tree_id, file_id)

	async def list(self, connection:SMBConnection):
		"""
		Lists all files and folders in the directory
		directory: SMBDirectory
		fills the SMBDirectory's data
		"""
		self.files = {}
		self.subdirs = {}
		
		desired_access = FileAccessMask.FILE_READ_DATA
		share_mode = ShareAccess.FILE_SHARE_READ
		create_options = CreateOptions.FILE_DIRECTORY_FILE | CreateOptions.FILE_SYNCHRONOUS_IO_NONALERT
		file_attrs = 0
		create_disposition = CreateDisposition.FILE_OPEN

		
		if not self.tree_id:
			tree_entry, err = await connection.tree_connect(self.get_share_path())
			if err is not None:
				raise err
			self.tree_id = tree_entry.tree_id
		
		file_id, err = await connection.create(self.tree_id, self.fullpath, desired_access, share_mode, create_options, create_disposition, file_attrs)
		if err is not None:
			return False, err
		try:
			while True:
				fileinfos, err = await connection.query_directory(self.tree_id, file_id)
				if err is not None:
					raise err
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

async def smb_mkdir(path:str, connection = None):
	"""
	Creates a new directory on the remote SMB server.
	"""
	if path.lower().startswith('smb'):
			from aiosmb.commons.connection.factory import SMBConnectionFactory
			factory = SMBConnectionFactory.from_url(path)
			if connection is None:
				connection = factory.get_connection()
				async with connection:
					_, err = await connection.login()
					if err is not None:
						raise err
					smbdir = factory.get_directory()
					_, err = await smbdir.create_remote(connection, smbdir.fullpath)
					if err is not None:
						raise err
					return
			else:
				smbdir = factory.get_directory()
				_, err = await smbdir.create_remote(connection, smbdir.fullpath)
				if err is not None:
					raise err
				return
	else:
		smbdir = SMBDirectory.from_remotepath(connection, path)
		_, err = await smbdir.create_remote(connection, smbdir.fullpath)
		if err is not None:
			raise err


async def smb_rmdir(path:str, connection = None):
	"""
	Removes a directory from the SMB server
	"""
	if path.lower().startswith('smb'):
			from aiosmb.commons.connection.factory import SMBConnectionFactory
			factory = SMBConnectionFactory.from_url(path)
			if connection is None:
				connection = factory.get_connection()
				async with connection:
					_, err = await connection.login()
					if err is not None:
						raise err
					smbdir = factory.get_directory()
					_, err = await smbdir.delete(connection)
					if err is not None:
						raise err
					return
			else:
				smbdir = factory.get_directory()
				_, err = await smbdir.delete(connection)
				if err is not None:
					raise err
				return
	else:
		smbdir = SMBDirectory.from_remotepath(connection, path)
		_, err = await smbdir.delete(connection)
		if err is not None:
			raise err

async def smb_walk(path:str, connection = None, fullpath = False):
	"""
	Enumerates files and subdirectories of a directory from the SMB server
	"""
	async def _walk(smbdir:SMBDirectory, connection, fullpath):
		_, err = await smbdir.list(connection)
		if err is None:
			yield smbdir, smbdir.get_subdir_paths(fullpath), smbdir.get_file_paths(fullpath)
			for subdir in smbdir.subdirs:
				async for x in _walk(smbdir.subdirs[subdir], connection, fullpath):
					yield x
		
		
	if path.lower().startswith('smb'):
			from aiosmb.commons.connection.factory import SMBConnectionFactory
			factory = SMBConnectionFactory.from_url(path)
			if connection is None:
				connection = factory.get_connection()
				async with connection:
					_, err = await connection.login()
					if err is not None:
						raise err
					smbdir = factory.get_directory()
			else:
				smbdir = factory.get_directory()
	else:
		smbdir = SMBDirectory.from_remotepath(connection, path)
	
	async for smbdir, subdirs, files in _walk(smbdir, connection, fullpath):
		yield smbdir, subdirs, files
		

async def amain():
	url = 'smb2+ntlm-password://TEST\\Administrator:Passw0rd!1@10.10.10.2/C$'
	#await smb_mkdir(url)
	
	from aiosmb.commons.connection.factory import SMBConnectionFactory
	connection = SMBConnectionFactory.from_url(url).get_connection()
	_, err = await connection.login()
	if err is not None:
		raise err

	async for smbdir, subdirs, files in smb_walk(url, connection, fullpath=True):
		print(smbdir.fullpath)
		print(subdirs)
		print(files)
		print('')
	#await smb_mkdir('C$\\temp\\temp2', connection=connection)
	#await smb_rmdir('C$\\temp\\temp2', connection=connection)
	#async with smb_open('C$/temp/repodata.json', 'rb', connection=connection) as f:
	#	while True:
	#		data, err = await f.read(1024)
	#		print(data)
	#		print(len(data))
	#		if data == b'':
	#			break
	


if __name__ == '__main__':
	import asyncio
	asyncio.run(amain())

