from aiosmb.commons.interfaces.directory import SMBDirectory
from aiosmb.wintypes.access_mask import *
from aiosmb.protocol.smb2.commands import *
from aiosmb.wintypes.fscc.structures.fileinfoclass import FileInfoClass

from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR
from typing import Callable, Awaitable, List, Dict, AsyncGenerator, Tuple, Union


class SMBShare:
	def __init__(self, name = None, stype = None, remark = None, fullpath = None):
		self.fullpath = fullpath
		self.unc_path = fullpath
		self.name = name
		self.type = stype
		self.remark = str(remark).replace('\x00', '') if remark is not None else None
		self.flags = None
		self.capabilities = None
		self.maximal_access = None
		self.tree_id = None
		self.security_descriptor = None
		
		self.files = {}
		self.subdirs = {}

	@staticmethod
	def from_unc(unc_path):
		return SMBShare(fullpath = unc_path)
	
	async def connect(self, connection):
		"""
		Connect to the share and fills connection related info in the SMBShare object
		FULLPATH MUST BE SPECIFIED ALREADY FOR THIS OBJECT!
		"""
		try:
			tree_entry, err = await connection.tree_connect(self.fullpath)
			if err is not None:
				raise err
			self.tree_id = tree_entry.tree_id
			self.maximal_access = tree_entry.maximal_access
			self.unc_path = self.fullpath
			init_dir = SMBDirectory()
			init_dir.tree_id = self.tree_id
			init_dir.fullpath = ''
			init_dir.unc_path = self.unc_path
			self.subdirs[''] = init_dir
			return True, None
			
		except Exception as e:
			return None, e

	async def get_security_descriptor(self, connection) -> Awaitable[Tuple[SECURITY_DESCRIPTOR, Union[Exception, None]]]:
		if self.security_descriptor is None:
			file_id = None
			try:
				tree_id = self.tree_id
				if tree_id is None:
					_, err = await self.connect(connection)
					if err is not None:
						raise err
					tree_id = self.tree_id
				if tree_id is not None:
					desired_access = FileAccessMask.READ_CONTROL
					share_mode = ShareAccess.FILE_SHARE_READ
					create_options = CreateOptions.FILE_DIRECTORY_FILE | CreateOptions.FILE_SYNCHRONOUS_IO_NONALERT
					file_attrs = 0
					create_disposition = CreateDisposition.FILE_OPEN
					file_id, err = await connection.create(tree_id, "", desired_access, share_mode,
														   create_options, create_disposition, file_attrs)
					if err is not None:
						raise err

					self.security_descriptor, err = await connection.query_info(
						tree_id,
						file_id,
						info_type=QueryInfoType.SECURITY,
						information_class=FileInfoClass.NONE,
						additional_information=SecurityInfo.ATTRIBUTE_SECURITY_INFORMATION | SecurityInfo.DACL_SECURITY_INFORMATION | SecurityInfo.OWNER_SECURITY_INFORMATION | SecurityInfo.GROUP_SECURITY_INFORMATION,
						flags=0,
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
		
	def __str__(self):
		t = '===== SHARE =====\r\n'
		for k in self.__dict__:
			if isinstance(self.__dict__[k], list):
				for item in self.__dict__[k]:
					t += '%s : %s\r\n' % (k, item)
			elif isinstance(self.__dict__[k], dict):
				for ks in self.__dict__[k]:
					t += '%s : %s\r\n' % (ks, self.__dict__[k][ks])
			else:
				t += '%s : %s\r\n' % (k, self.__dict__[k])
		
		return t
