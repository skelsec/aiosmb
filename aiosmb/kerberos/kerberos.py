#
#
# This is just a simple interface to the minikerberos library to support SPNEGO
# 

from minikerberos.common import *
from minikerberos.aiocommunication import *

# SMBKerberosCredential

class SMBKerberos:
	def __init__(self, settings):
		self.settings = settings
		self.mode = None
		self.ccred = None
		self.ksoc = None
		self.target = None
		self.kc = None
		
		self.session_key = None
		
		self.setup()
		
	def setup(self):
		self.mode = self.settings.mode
		self.ccred = self.settings.ccred
		self.ksoc = self.settings.ksoc
		self.target = self.settings.target
		
		
		self.kc = KerbrosCommAIO(self.ccred, self.ksoc)
		
	
	def get_session_key(self):
		return self.session_key.contents
	
	async def authenticate(self, authData, flags = None, seq_number = 0):
		tgt = await self.kc.get_TGT()
		tgs, encpart, self.session_key = await self.kc.get_TGS(self.target)
		apreq = self.kc.construct_apreq(tgs, encpart, self.session_key, flags = flags, seq_number = seq_number)
		
		return apreq, False