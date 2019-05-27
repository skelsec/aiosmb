
from aiosmb.commons.smbcontainer import *
from aiosmb.commons.access_mask import *
from aiosmb.protocol.smb2.commands import *

class SMBFileReader:
	def __init__(self, connection = None):
		self.connection = connection
		self.mode = None
		self.file = None
		self.share = None
		
		self.position = 0
		self.is_pipe = False
		
	async def __aenter__(self):
		return self
		
	async def __aexit__(self, exc_type, exc, traceback):
		await self.close()
		
	async def __connect_share(self, share):
		"""
		Connect to the share and fills connection related info in the SMBShare object
		"""
		tree_entry = await self.connection.tree_connect(share.fullpath)
		share.tree_id = tree_entry.tree_id
		share.maximal_access = tree_entry.maximal_access
		
		return
		
	async def __read(self, size, offset):
		"""
		This is the main function for reading.
		It does not do buffering, so if more data is returned it will just discard it
		If less data is returned than requested it will do more reads until the requested size is reached.
		Do not call this directly as it could go in an infinite loop 
		"""
		if self.is_pipe == True:
			data, remaining = await self.connection.read(self.share.tree_id, self.file.file_id, offset = offset, length = size)
			return data
		
		buffer = b''
		while len(buffer) <= size:
			data, remaining = await self.connection.read(self.share.tree_id, self.file.file_id, offset = offset, length = size)
			buffer += data
			
		return buffer[:size]
		
	async def __write(self, data, offset = 0):
		remaining = len(data)
		total_bytes_written = 0
		
		while remaining != 0:
			bytes_written = await self.connection.write(self.share.tree_id, self.file.file_id, data[offset:len(data)], offset = offset)
			total_bytes_written += bytes_written
			remaining -= bytes_written
			offset += bytes_written
		
		return total_bytes_written
		
	async def open(self, filename, mode = 'r'):
		self.mode = mode
		if 'p' in self.mode:
			self.is_pipe = True
		
		if isinstance(filename, str):
			#then it's a string path, we need to create an SMBFile
			if filename.startswith('\\\\') != True:
				raise Exception('Filename as a string MUST be in \\\\<server>\\<share>\\....\\file format!')
			
			server_name, t , file_path = filename[2:].split('\\',2)
			share_name = '\\\\' + server_name + '\\' + t
			self.share = SMBShare()
			self.share.fullpath = share_name
			self.file = SMBFile()
			self.file.parent_share = self.share
			self.fullpath = file_path
		
		elif isinstance(filename, SMBFile):
			#this arrived from somewhere else
			if filename.parent_share.fullpath is None:
				raise Exception('Parent share MUST be speicfied if open is called with SMBFile object as filename!') #otherwise noone knows the treeid to connect to...
			self.share = SMBShare()
			self.share.fullpath = filename.parent_share.fullpath
			self.file = SMBFile()
			self.file.fullpath = filename.fullpath
			
		else:
			raise Exception('Filename MUST be either SMBFile or a full path string to the file')
		
		#first, connecting to the share. we create a new treeid regardless of it already exists one for this share or not
		await self.__connect_share(self.share)
		
		#then connect to file
		if 'r' in mode and 'w' in mode:
			raise ValueError('must have exactly one of read/write mode')
			
		if 'r' in mode:
			desired_access = FileAccessMask.FILE_READ_DATA | FileAccessMask.FILE_READ_ATTRIBUTES
			share_mode = ShareAccess.FILE_SHARE_READ
			create_options = CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_SYNCHRONOUS_IO_NONALERT 
			file_attrs = 0
			create_disposition = CreateDisposition.FILE_OPEN
			
			self.file.file_id, smb_reply = await self.connection.create(self.share.tree_id, self.fullpath, desired_access, share_mode, create_options, create_disposition, file_attrs, return_reply = True)
			self.file.size = smb_reply.EndofFile
			
		elif 'w' in mode:
			desired_access = FileAccessMask.GENERIC_READ | FileAccessMask.GENERIC_WRITE
			share_mode = ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE
			create_options = CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_SYNCHRONOUS_IO_NONALERT 
			file_attrs = 0
			create_disposition = CreateDisposition.FILE_OPEN
			
			self.file.file_id, smb_reply = await self.connection.create(self.share.tree_id, self.fullpath, desired_access, share_mode, create_options, create_disposition, file_attrs, return_reply = True)
			self.file.size = smb_reply.EndofFile
			
		else:
			raise Exception('ONLY read and write is supported at the moment!')
			
		#if we don't know the actual file fize, we need to ask the server
		
			
		
	async def seek(self, offset, whence = 0):
		if whence == 0:
			if offset < 0:
				raise Exception('Offset must be > 0 when whence is 0')
			if offset > self.file.size:
				raise Exception('Seeking outside of file size!')
			self.position = offset
		
		elif whence == 1:
			if 0 < self.position + offset < self.file.size:
				self.position += offset
			else:
				raise Exception('Seeking outside of file size!')
		
		elif whence == 2:
			if 0 < self.file.size + offset < self.file.size:
				self.position = self.file.size + offset
			else:
				raise Exception('Seeking outside of file size!')
		
	async def read(self, size = -1):
		if size == 0:
			raise Exception('Cant read 0 bytes')
			
		elif size == -1:
			data = await self.__read(self.file.size - self.position, self.position)
			if self.is_pipe == False:
				self.position += len(data)
			return data
			
		elif size > 0:
			if size + self.position > self.file.size:
				raise Exception('More data requested than filesize!')
			data = await self.__read(size, self.position)
			self.position += len(data)
			return data
			
			
	async def write(self, data):
		count = await self.__write(data, self.position)
		if self.is_pipe == False:
			self.position += count
		
	async def flush(self):
		if self.file is None:
			return
		if 'r' in self.mode:
			return
		else:
			await self.connection.flush(self.share.tree_id, self.file.file_id)
		
	async def close(self):
		if self.file is not None:
			await self.flush()
			await self.connection.close(self.share.tree_id, self.file.file_id)
		if self.share is not None:
			await self.connection.tree_disconnect(self.share.tree_id)
		