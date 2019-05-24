#
#
# This is just a simple interface to the minikerberos library to support SPNEGO
# 

from minikerberos.common import *
from minikerberos.aiocommunication import *

settings = {
	'mode' : 'CLIENT',
	'connection_string' : '',
	'target_string': '',
	'dc_ip' : '',
	'connection' : None,
	'target' : None,

}

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
		self.mode = self.settings['mode']
		if 'connection_string' in self.settings:
			self.ccred = KerberosCredential.from_connection_string( self.settings['connection_string'])
		elif 'connection' in self.settings:
			#the object is passed in settings
			self.ccred = self.settings['connection']
		else:
			raise Exception('Either connection or connection_string MUST be specified in kerberos settings!')
			
		if 'target_string' in self.settings:
			self.target = KerberosTarget.from_target_string( self.settings['target_string'])
		elif 'target' in self.settings:
			self.target =self.settings['target']
		else:
			raise Exception('Either target or target_string MUST be specified in kerberos settings')
			
		if 'dc_ip' in self.settings:
			self.ksoc = KerberosSocketAIO(self.settings['dc_ip'])
		else:
			raise Exception('DC IP MUST be specified in kerberos settings')
		
		self.kc = KerbrosCommAIO(self.ccred, self.ksoc)
		
	
	def get_session_key(self):
		return self.session_key.contents
	
	async def authenticate(self, authData):
		tgt = await self.kc.get_TGT()
		tgs, encpart, self.session_key = await self.kc.get_TGS(self.target)
		apreq = self.kc.construct_apreq(tgs, encpart, self.session_key)
		
		return apreq, False