from aiosmb.commons.interfaces.directory import SMBDirectory


class SMBShare:
	def __init__(self, name = None, stype = None, remark = None, fullpath = None):
		self.fullpath = fullpath
		self.unc_path = fullpath
		self.name = name
		self.type = stype
		self.remark = remark
		self.flags = None
		self.capabilities = None
		self.maximal_access = None
		self.tree_id = None
		
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