#
#
# This is just a simple interface to the winsspi library to support Kerberos
# 
from winsspi.sspi import KerberosSMBSSPI

settings = {
	'mode' : 'CLIENT',
	'client' : None,
	'target' : None,
}

class SMBKerberosSSPI:
	def __init__(self, settings):
		self.settings = settings
		self.mode = 'CLIENT'
		self.ksspi = KerberosSMBSSPI()
		self.client = None
		self.target = None
		
		self.setup()
		
	def setup(self):
		if 'mode' in self.settings:
			self.mode = self.settings['mode'].upper()
		
		if 'client' in self.settings:
			self.mode = self.settings['client']
			
		if 'target' in self.settings:
			self.target = self.settings['target']
		else:
			raise Exception('Target keyword must be specified in Kerberos!')
	
	def get_session_key(self):
		return self.ksspi.get_session_key()
	
	async def authenticate(self, authData = None):
		#authdata is only for api compatibility reasons
		apreq = self.ksspi.get_ticket_for_spn(self.target)
		return apreq, False
		