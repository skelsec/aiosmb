from aiosmb.commons.interfaces.directory import SMBDirectory


class SMBShare:
	def __init__(self, name = None, stype = None, remark = None, fullpath = None):
		self.fullpath = fullpath
		self.unc_path = None
		self.name = name
		self.type = stype
		self.remark = remark
		self.flags = None
		self.capabilities = None
		self.maximal_access = None
		self.tree_id = None
		
		self.files = {}
		self.subdirs = {}
	
	async def connect(self, connection):
		"""
		Connect to the share and fills connection related info in the SMBShare object
		FULLPATH MUST BE SPECIFIED ALREADY FOR THIS OBJECT!
		"""
		tree_entry = await connection.tree_connect(self.fullpath)
		self.tree_id = tree_entry.tree_id
		self.maximal_access = tree_entry.maximal_access
		self.unc_path = self.fullpath
		init_dir = SMBDirectory()
		init_dir.tree_id = self.tree_id
		init_dir.fullpath = ''
		init_dir.unc_path = self.unc_path
		#init_dir.name = ''
		self.subdirs[''] = init_dir
		
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