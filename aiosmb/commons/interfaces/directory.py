
import copy
import asyncio
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
		self.security_descriptor = None
		
		self.files = {}
		self.subdirs = {}

	@staticmethod
	def from_uncpath(unc_path):
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
	def from_remotepath(connection, remotepath):
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
	async def delete_unc(connection, remotepath):
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
	async def create_remote(connection, remotepath):
		try:
			remfile = SMBDirectory.from_remotepath(connection, remotepath)
			tree_entry, err = await connection.tree_connect(remfile.share_path)
			if err is not None:
				raise err
			tree_id = tree_entry.tree_id

			desired_access = FileAccessMask.GENERIC_ALL
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

	async def delete(self, connection):
		try:
			if self.file_id is not None:
				# if the directory is open, first we need to close it
				await connection.close(self.tree_id, self.file_id)
			return SMBDirectory.delete_unc(connection, self.unc_path)
		except Exception as e:
			return False, e

	async def get_security_descriptor(self, connection):
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
		
	async def create_subdir(self, dir_name, connection):
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
					FileAccessMask.GENERIC_ALL, 
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
	
	async def delete_subdir(self, dir_name):
		raise Exception('delete subdir not implemented!')

	async def list_r(self, connection, depth = 3, maxentries = None, fetch_dir_sd = False, fetch_file_sd = False, exclude_dir = []):
		"""
		recursive list files and folders
		Beware this will clear out the lists of files/folders to save memory!
		"""
		if depth == 0:
			return
		depth -= 1
		ctr = 0

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
				obj.tree_id = self.tree_id
				async for e,t,err in obj.list_r(connection, depth, maxentries = maxentries, exclude_dir = exclude_dir):
					yield e,t,err
					await asyncio.sleep(0)


	async def list_gen(self, connection):
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

	async def list(self, connection):
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