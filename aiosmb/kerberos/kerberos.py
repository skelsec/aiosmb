#
#
# This is just a simple interface to the minikerberos library to support SPNEGO
# 

from minikerberos.common import *
from minikerberos.aiocommunication import *

class SMBKerberos:
	def __init__(self, settings):
		self.settings = settings
		self.ccred = None
		self.ksoc = None
		self.target = None
		self.kc = None
		
		self.session_key = None
		
		
		self.setup()
		
	def setup(self):
		
		self.ccred = KerberosCredential
		self.ksoc = KerberosSocketAIO
		self.target = KerberosTarget
		self.kc = KerbrosCommAIO(self.ccred, self.ksoc)
		
	
	def get_session_key(self):
		return self.session_key.contents
	
	async def authenticate(self, authData):
		tgt = await self.kc.get_TGT()
		tgs, encpart, self.session_key = await self.kc.get_TGS(self.target)
		return tgs