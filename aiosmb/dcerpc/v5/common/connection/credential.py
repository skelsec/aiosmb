import enum

class DCERPCCredentialsSecretType(enum.Enum):
	NT = 'NT'
	PASSWORD = 'PASSWORD'
	AES = 'AES'
	RC4 = 'RC4'
	CCACHE = 'CCACHE'
	NONE = 'NONE'

class DCERPCAuthProtocol(enum.Enum):
	NTLM = 'NTLM'
	KERBEROS = 'KERBEROS'
	SSPI_KERBEROS = 'SSPI_KERBEROS'
	SSPI_NTLM = 'SSPI_NTLM'
	MULTIPLEXOR_NTLM = 'MULTIPLEXOR_NTLM'
	MULTIPLEXOR_KERBEROS = 'MULTIPLEXOR_KERBEROS'
	MULTIPLEXOR_SSL_NTLM = 'MULTIPLEXOR_SSL_NTLM'
	MULTIPLEXOR_SSL_KERBEROS = 'MULTIPLEXOR_SSL_KERBEROS'

class DCERPCCredential:
	def __init__(self, username = None, domain = None, secret = None, secret_type = None, authentication_type = None, settings = None, target = None):
		self.username = username
		self.domain = domain
		self.secret = secret
		self.secret_type = secret_type #SMBCredentialsSecretType
		self.target = target #for kerberos authentication
		
		self.authentication_type = authentication_type #kerberos or NTLM or ...
		self.settings = settings

	def __str__(self):
		t = '==== DCERPCCredential ====\r\n'
		for k in self.__dict__:
			t += '%s: %s\r\n' % (k, self.__dict__[k])
			
		return t
		
class DCERPCKerberosCredential:
	def __init__(self):
		self.mode = 'CLIENT'
		self.connection = None #KerberosCredential
		self.target = None #KerberosTarget
		self.ksoc = None #KerberosSocketAIO
		self.ccred = None
		
class DCERPCKerberosSSPICredential:
	def __init__(self):
		self.mode = 'CLIENT'
		self.client = None
		self.password = None
		self.target  = None
		
class DCERPCNTLMSSPICredential:
	def __init__(self):
		self.mode = 'CLIENT'
		self.client = None
		self.passwrd = None
		
class DCERPCNTLMCredential:
	def __init__(self):
		self.username = None
		self.domain = ''
		self.password = None
		self.workstation = None
		self.is_guest = False
		self.nt_hash = None
		self.lm_hash = None

class DCERPCMultiplexorCredential:
	def __init__(self):
		self.mode = 'CLIENT'
		self.type = 'NTLM'
		self.username = '<CURRENT>'
		self.domain = '<CURRENT>'
		self.password = '<CURRENT>'
		self.target = None
		self.is_guest = False
		self.is_ssl = False
		self.mp_host = None
		self.mp_port = None
		self.mp_username = None
		self.mp_domain = None
		self.mp_password = None
		self.agent_id = None

	def get_url(self):
		url_temp = 'ws://%s:%s'
		if self.is_ssl is True:
			url_temp = 'wss://%s:%s'
		url = url_temp % (self.mp_host, self.mp_port)
		return url

	def parse_settings(self, settings):
		self.mp_host = settings['host'][0]
		self.mp_port = settings['port'][0]
		if self.mp_port is None:
			self.mp_port = '9999'
		if 'user' in settings:
			self.mp_username = settings.get('user')[0]
		if 'domain' in settings:
			self.mp_domain = settings.get('domain')[0]
		if 'password' in settings:
			self.mp_password = settings.get('password')[0]
		self.agent_id = settings['agentid'][0]