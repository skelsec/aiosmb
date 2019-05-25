#
#
# This is just a simple interface to the winsspi library to support Kerberos
# 
from winsspi.sspi import NTLMSMBSSPI

class SMBNTLMSSPI:
	def __init__(self, settings):
		self.settings = settings
		self.mode = None #'CLIENT'
		self.sspi = NTLMSMBSSPI()
		self.client = None
		self.target = None
		
		self.setup()
		
	def setup(self):
		self.mode = self.settings.mode.upper()
		self.client = self.settings.client
		self.password = self.settings.password
	
	def get_session_key(self):
		return self.sspi.get_session_key()
	
	async def authenticate(self, authData = None):
		if self.mode == 'CLIENT':
			if authData is None:
				return self.sspi.negotiate()
			else:
				return self.sspi.authenticate(authData)
			