from pathlib import PureWindowsPath
from aiosmb.wintypes.access_mask import *
from aiosmb.protocol.smb2.commands import *
from aiosmb.wintypes.fscc.structures.fileinfoclass import FileInfoClass
from aiosmb.protocol.smb2.commands.query_info import SecurityInfo
import io


class SMBFile:
	def __init__(self):
		self.tree_id = None
		self.parent_dir = None
		self.fullpath = None
		self.unc_path = None
		self.share_path = None
		self.name = None
		self.size = None
		self.creation_time = None
		self.last_access_time = None
		self.last_write_time = None
		self.change_time = None
		self.allocation_size = None
		self.attributes = None
		self.file_id = None
		self.sid = None

		#internal
		self.__connection = None
		self.__position = 0
		self.is_pipe = False

	@staticmethod
	def from_uncpath(unc_path):
		"""
		Creates SMBFile object from the UNC path supplied.
		Example uncpath: \\\\127.0.0.1\\C$\\temp\\test.exe
		"""
		unc = PureWindowsPath(unc_path)
		f = SMBFile()
		f.share_path = unc.drive
		f.fullpath = '\\'.join(unc.parts[1:])
		
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
		return SMBFile.from_uncpath(unc)

	@staticmethod
	async def delete_unc(connection, remotepath):
		try:
			remfile = SMBFile.from_remotepath(connection, remotepath)
			tree_entry = await connection.tree_connect(remfile.share_path)
			tree_id = tree_entry.tree_id

			desired_access = FileAccessMask.DELETE | FileAccessMask.FILE_READ_ATTRIBUTES
			share_mode = ShareAccess.FILE_SHARE_DELETE
			create_options = CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_DELETE_ON_CLOSE 
			create_disposition = CreateDisposition.FILE_OPEN
			file_attrs = 0

			file_id = await connection.create(tree_id, remfile.fullpath, desired_access, share_mode, create_options, create_disposition, file_attrs, return_reply = False)
			if file_id is not None:
				await connection.close(tree_id, file_id)

			await connection.tree_disconnect(tree_id)
			return True, None
		
		except Exception as e:
			return False, e

	@staticmethod
	async def delete(connection, remotepath):
		try:
			remfile = SMBFile.from_remotepath(connection, remotepath)
			tree_entry = await connection.tree_connect(remfile.share_path)
			tree_id = tree_entry.tree_id

			desired_access = FileAccessMask.DELETE | FileAccessMask.FILE_READ_ATTRIBUTES
			share_mode = ShareAccess.FILE_SHARE_DELETE
			create_options = CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_DELETE_ON_CLOSE 
			create_disposition = CreateDisposition.FILE_OPEN
			file_attrs = 0

			file_id = await connection.create(tree_id, remfile.fullpath, desired_access, share_mode, create_options, create_disposition, file_attrs, return_reply = False)
			if file_id is not None:
				await connection.close(tree_id, file_id)

			await connection.tree_disconnect(tree_id)
			return True, None
		
		except Exception as e:
			return False, e

	async def get_security_descriptor(self, connection):
		if self.sid is None:
			file_id = None
			try:
				desired_access = FileAccessMask.READ_CONTROL
				share_mode = ShareAccess.FILE_SHARE_READ
				create_options = CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_SYNCHRONOUS_IO_NONALERT 
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

	async def __read(self, size, offset):
		"""
		This is the main function for reading.
		It does not do buffering, so if more data is returned it will just discard it
		If less data is returned than requested it will do more reads until the requested size is reached.
		Do not call this directly as it could go in an infinite loop 
		"""
		if self.is_pipe == True:
			data, remaining = await self.__connection.read(self.tree_id, self.file_id, offset = offset, length = size)
			return data
		
		buffer = b''
		if size > self.__connection.MaxReadSize:
			i, rem = divmod(size, self.__connection.MaxReadSize)
			for _ in range(i+1):
				data, remaining = await self.__connection.read(self.tree_id, self.file_id, offset = offset, length = self.__connection.MaxReadSize)
				offset += len(data)
				buffer += data
			
			return buffer[:size]
		else:
			data, remaining = await self.__connection.read(self.tree_id, self.file_id, offset = offset, length = self.__connection.MaxReadSize)
			buffer += data
			
			return buffer[:size]

	async def __write(self, data, position_in_file = 0):
		"""
		Data must be bytes
		"""
		remaining = len(data)
		total_bytes_written = 0
		offset = 0
		
		while remaining != 0:
			bytes_written = await self.__connection.write(self.tree_id, self.file_id, data[offset:len(data)], offset = position_in_file + offset)
			total_bytes_written += bytes_written
			remaining -= bytes_written
			offset += bytes_written
		
		return total_bytes_written

	async def open(self, connection, mode = 'r'):
		try:
			self.__connection = connection
			self.mode = mode
			if 'p' in self.mode:
				self.is_pipe = True
				self.size = 0
			
			if not self.tree_id:
				tree_entry = await connection.tree_connect(self.share_path)
				self.tree_id = tree_entry.tree_id
			

			#then connect to file
			if 'r' in mode and 'w' in mode:
				raise ValueError('must have exactly one of read/write mode')
				
			if 'r' in mode:
				desired_access = FileAccessMask.FILE_READ_DATA | FileAccessMask.FILE_READ_ATTRIBUTES
				share_mode = ShareAccess.FILE_SHARE_READ
				create_options = CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_SYNCHRONOUS_IO_NONALERT 
				file_attrs = 0
				create_disposition = CreateDisposition.FILE_OPEN
				
				self.file_id, smb_reply = await connection.create(self.tree_id, self.fullpath, desired_access, share_mode, create_options, create_disposition, file_attrs, return_reply = True)
				self.size = smb_reply.EndofFile
				
			elif 'w' in mode:
				desired_access = FileAccessMask.GENERIC_READ | FileAccessMask.GENERIC_WRITE
				share_mode = ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE
				create_options = CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_SYNCHRONOUS_IO_NONALERT 
				file_attrs = 0
				create_disposition = CreateDisposition.FILE_OPEN_IF #FILE_OPEN ? might cause an issue?
				
				self.file_id, smb_reply = await connection.create(self.tree_id, self.fullpath, desired_access, share_mode, create_options, create_disposition, file_attrs, return_reply = True)
				self.size = smb_reply.EndofFile
				
			else:
				raise Exception('ONLY read and write is supported at the moment!')
			
			return True, None
		except Exception as e:
			return False, e
		
	async def seek(self, offset, whence = 0):
		if whence == 0:
			if offset < 0:
				raise Exception('Offset must be > 0 when whence is 0')
			if offset > self.size:
				raise Exception('Seeking outside of file size!')
			self.__position = offset
		
		elif whence == 1:
			if 0 < self.__position + offset < self.size:
				self.__position += offset
			else:
				raise Exception('Seeking outside of file size!')
		
		elif whence == 2:
			if 0 < self.size + offset < self.size:
				self.__position = self.size + offset
			else:
				raise Exception('Seeking outside of file size!')
		
	async def read(self, size = -1):
		if self.is_pipe is True:
			data = await self.__read(size, 0)
			return data
		
		if size > self.size:
			raise Exception('Requested read size %s is larger than the file size %s' % (hex(size), hex(self.size)))

		if size == 0:
			raise Exception('Cant read 0 bytes')
			
		elif size == -1:
			data = await self.__read(self.size - self.__position, self.__position)
			self.__position += len(data)
			
			return data
			
		elif size > 0:
			if self.__position == self.size:
				return None
			if size + self.__position > self.size:
				size = self.size - self.__position
			data = await self.__read(size, self.__position)
			self.__position += len(data)
			return data

	async def read_chunked(self, size = -1, chunksize = -1):
		"""
		Much like read, but yields chauks of chunksize untill the full size is read
		Use this when reading large files as a whole, as this method doesn't caches 
		the whole data read in memory, only chunskize
		chunksize -1 will use the maximum chunk allowed by the underlying connection layer, it is advised to not set manually!
		"""
		if self.is_pipe is True:
			raise Exception('Cant stream pipes!')

		if chunksize == -1:
			chunksize = self.__connection.MaxReadSize

		if size == 0:
			yield None
			
		elif size == -1:
			while True:
				req_size = chunksize
				if self.size - self.__position < chunksize:
					req_size = self.size - self.__position
					if req_size == 0:
						#consumed all data
						yield None
						raise StopIteration

				data = await self.__read(req_size, self.__position)
				self.__position += len(data)
				yield data
			
		elif size > 0:
			if self.__position == self.size:
				yield None
				raise StopIteration
			if size + self.__position > self.size:
				size = self.size - self.__position

			while True:
				req_size = chunksize
				if size - self.__position < chunksize:
					req_size = size - self.__position
				if req_size == 0:
					yield None
					raise StopIteration
				data = await self.__read(req_size, self.__position)
				self.__position += len(data)
				yield data
			
	async def write(self, data):
		if len(data) < self.__connection.MaxWriteSize:
			count = await self.__write(data, self.__position)
			if self.is_pipe == False:
				self.__position += count
			return count

		total_writen = 0

		while total_writen != len(data) :
			count = await self.__write(data[total_writen:total_writen+self.__connection.MaxWriteSize], self.__position)
			total_writen += count
			if self.is_pipe == False:
				self.__position += count		

		return total_writen

	async def write_buffer(self, buffer):
		"""
		Doesnt work with pipes!
		"""
		if self.is_pipe == True:
			raise Exception('Doesnt work with pipes!')
		
		total_writen = 0
		while True:
			chunk = buffer.read(self.__connection.MaxWriteSize)
			if len(chunk) == 0:
				return total_writen
			bytes_written = await self.__write(chunk, self.__position)

			self.__position += bytes_written
			total_writen += bytes_written
		
	async def flush(self):
		if 'r' in self.mode:
			return
		else:
			await self.__connection.flush(self.tree_id, self.file_id)
		
	async def close(self):
		await self.flush()
		await self.__connection.close(self.tree_id, self.file_id)
	
		
	def __str__(self):
		t = '===== FILE =====\r\n'
		for k in self.__dict__:
			if k.startswith('parent_'):
				continue
			t += '%s : %s\r\n' % (k, self.__dict__[k])
		
		return t