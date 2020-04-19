	
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
		t += ':'.join(['ntlm', str(self.domain),str(self.username),str(self.user_account_status),str(self.object_sid),self.lm_hash.hex(), self.nt_hash.hex(),str(self.pwd_last_set)])
		t += '\r\n'
		for i, x in enumerate(zip(self.lm_history,self.nt_history)):
			lm, nt = x
			t += ':'.join(['ntlm_history', str(self.domain),str(self.username),str(self.user_account_status),str(self.object_sid), lm.hex(), nt.hex(), 'history_%d'% (i+1) ])
			t += '\r\n'
		for ktype, key in self.kerberos_keys:
			t += ':'.join(['kerberos',str(self.domain),str(self.username),str(self.object_sid),ktype,key.hex()])
			t += '\r\n'
		for key in self.cleartext_pwds:
			t += ':'.join(['cleartext',str(self.domain),str(self.username),str(self.object_sid),key])
			t += '\r\n'
			
		return t