

class SMBShare:
	def __init__(self, name = None, type = None, remark = None, fullpath = None):
		self.fullpath = fullpath
		self.name = name
		self.type = type
		self.remark = remark
		self.flags = None
		self.capabilities = None
		self.maximal_access = None
		self.tree_id = None
		
		self.files = {}
		self.subdirs = {}
		
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
		
class SMBDirectory:
	def __init__(self):
		self.parent_share = None
		self.fullpath = None
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
		
	def __str__(self):
		t = '===== DIRECTORY =====\r\n'
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
		
class SMBFile:
	def __init__(self):
		self.parent_share = None
		self.parent_dir = None
		self.fullpath = None
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
		
	def __str__(self):
		t = '===== FILE =====\r\n'
		for k in self.__dict__:
			if k.startswith('parent_'):
				continue
			t += '%s : %s\r\n' % (k, self.__dict__[k])
		
		return t
		
class SMBUserSession:
	def __init__(self, username = None, ip_addr = None):
		self.username = username
		self.ip_addr = ip_addr
		
class SMBLocalGroup:
	def __init__(self, name = None, sid = None, members = {}):
		self.name = name
		self.sid = sid
		self.members = members
		
class SMBDomain:
	def __init__(self):
		self.name = None
		self.sid = None
		
class SMBHostInfo:
	def __init__(self):
		self.sessions = []
		self.domains = []
		self.groups = []
		self.shares = []
		self.finger_info = None
		
		
class SMBUserSecrets:
	def __init__(self):
		self.domain = None
		self.username = None
		self.nt_hash = None
		self.lm_hash = None
		
		self.object_sid = None
		self.pwd_last_set = None
		self.user_account_status = None
		
		self.lm_history = []
		self.nt_history = []
		self.kerberos_keys = []
		self.cleartext_pwds = []
	
	def to_dict(self):
		t = {}
		t['domain'] = self.domain
		t['username'] = self.username
		t['nt_hash'] = self.nt_hash.hex()
		t['lm_hash'] = self.lm_hash.hex()

		t['object_sid'] = str(self.object_sid)
		t['pwd_last_set'] = str(self.pwd_last_set)
		t['user_account_status'] = str(self.user_account_status)
		
		t['lm_history'] = []
		for i, lm in enumerate(self.lm_history):
			t['lm_history'].append(lm.hex())
		
		t['nt_history'] = []
		for i, nt in enumerate(self.nt_history):
			t['nt_history'].append(nt.hex())
		
		t['cleartext_pwds'] = []
		for i, pwd in enumerate(self.cleartext_pwds):
			t['cleartext_pwds'].append(str(pwd))
			
		t['kerberos_keys'] = []
		for ktype, key in self.kerberos_keys:
			t['kerberos_keys'].append([str(ktype), key.hex()])

		
		return t
	def __str__(self):
		t = ''
		t += ':'.join([str(self.domain),str(self.username),str(self.user_account_status),self.lm_hash.hex(), self.nt_hash.hex(),str(self.pwd_last_set)])
		t += '\r\n'
		for i, x in enumerate(zip(self.lm_history,self.nt_history)):
			lm, nt = x
			t += ':'.join([str(self.domain),str(self.username),str(self.user_account_status), self.lm_hash.hex(), self.nt_hash.hex(), 'history_%d'% i ])
			t += '\r\n'
		for ktype, key in self.kerberos_keys:
			t += ':'.join([str(self.domain),str(self.username),ktype,key.hex()])
			t += '\r\n'
		for key in self.cleartext_pwds:
			t += ':'.join([str(self.domain),str(self.username),ktype,key.hex()])
			t += '\r\n'
			
		return t
		