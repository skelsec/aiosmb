#
#
# This is just a simple interface to the winsspi library to support Kerberos
# 
from winsspi.sspi import KerberosSMBSSPI

# SMBKerberosSSPICredential:

class SMBKerberosSSPI:
	def __init__(self, settings):
		self.settings = settings
		self.mode = 'CLIENT'
		self.ksspi = KerberosSMBSSPI()
		self.client = None
		self.target = None
		
		self.setup()
		
	def setup(self):
		self.mode = self.settings.mode
		self.client = self.settings.client
		self.target = self.settings.target
		
		input(self.target)
	
	def get_session_key(self):
		return self.ksspi.get_session_key()
	
	async def authenticate(self, authData = None):
		#authdata is only for api compatibility reasons
		apreq = self.ksspi.get_ticket_for_spn(self.target)
		return apreq, False
		