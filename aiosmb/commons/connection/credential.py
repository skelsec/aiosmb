import enum
import platform
import uuid


class SMBCredentialTypes(enum.Enum):
	NTLM_NT = 'ntlm-nt'
	NTLM_PASSWORD = 'ntlm-password'
	NTLM_PWPROMPT = 'ntlm-pwprompt'
	NTLM_PWHEX = 'ntlm-pwhex'
	NTLM_PWB64 = 'ntlm-pwb64'
	SSPI_NTLM = 'sspi-ntlm'
	SSPI_KERBEROS = 'sspi-kerberos'
	MULTIPLEXOR_NTLM = 'multiplexor-ntlm'
	MULTIPLEXOR_KERBEROS = 'multiplexor-kerberos'
	KERBEROS_PASSWORD = 'kerberos-password'
	KERBEROS_PWPROMPT = 'kerberos-pwprompt'
	KERBEROS_PWHEX = 'kerberos-pwhex'
	KERBEROS_PWB64 = 'kerberos-pwb64'
	KERBEROS_AES = 'kerberos-aes'
	KERBEROS_RC4 = 'kerberos-rc4'
	KERBEROS_CCACHE = 'kerberos-ccache'
	KERBEROS_KIRBI = 'kerberos-kirbi'

class SMBCredentialsSecretType(enum.Enum):
	NT = 'NT'
	PASSWORD = 'PASSWORD'
	PWPROMPT = 'PWPROMPT'
	PWHEX = 'PWHEX'
	PWB64 = 'PWB64'
	AES = 'AES'
	RC4 = 'RC4'
	CCACHE = 'CCACHE'
	KEYTAB = 'KEYTAB'
	KIRBI = 'KIRBI'
	NONE = 'NONE'

class SMBAuthProtocol(enum.Enum):
	NTLM = 'NTLM'
	KERBEROS = 'KERBEROS'
	SSPI_KERBEROS = 'SSPI_KERBEROS'
	SSPI_NTLM = 'SSPI_NTLM'
	MULTIPLEXOR_NTLM = 'MULTIPLEXOR_NTLM'
	MULTIPLEXOR_KERBEROS = 'MULTIPLEXOR_KERBEROS'
	MULTIPLEXOR_SSL_NTLM = 'MULTIPLEXOR_SSL_NTLM'
	MULTIPLEXOR_SSL_KERBEROS = 'MULTIPLEXOR_SSL_KERBEROS'
	MPN_SSL_NTLM = 'MPN_SSL_NTLM'
	MPN_NTLM = 'MPN_NTLM'
	MPN_SSL_KERBEROS = 'MPN_SSL_KERBEROS'
	MPN_KERBEROS = 'MPN_KERBEROS'
	WSNET_NTLM = 'WSNET_NTLM'
	WSNET_KERBEROS = 'WSNET_KERBEROS'
	SSPIPROXY_KERBEROS = 'SSPIPROXY_KERBEROS'
	SSPIPROXY_NTLM = 'SSPIPROXY_NTLM'

class SMBCredential:
	def __init__(self, username = None, domain = None, secret = None, secret_type = None, authentication_type = None, settings = None, target = None):
		self.username = username
		self.domain = domain
		self.secret = secret
		self.secret_type = secret_type #SMBCredentialsSecretType
		self.target = target #for kerberos authentication
		
		self.authentication_type = authentication_type #kerberos or NTLM or ...
		self.settings = settings
			
		#domain/user/auth_type/secret_type:secret@target_ip_hostname_fqdn:target_port/dc_ip

	def __str__(self):
		t = '==== SMBCredential ====\r\n'
		for k in self.__dict__:
			t += '%s: %s\r\n' % (k, self.__dict__[k])
			
		return t
	
	@staticmethod
	def from_credential_string(s):
		"""
		Making users life more conveinent
		"""
		return SMBCredential.from_connection_string(s + '@')

	@staticmethod
	def from_connection_string(s):
		creds = SMBCredential()
		
		t, target = s.rsplit('@', 1)
		creds.domain, t = t.split('/', 1)
		creds.username, t = t.split('/', 1)
		if t.find('/') != -1:
			auth_type , t = t.split('/', 1)
			secret_type, creds.secret = t.split(':',1)
			creds.secret_type = SMBCredentialsSecretType(secret_type.upper())
		else:
			auth_type = t
			creds.secret_type = SMBCredentialsSecretType.NONE
		creds.authentication_type = SMBAuthProtocol(auth_type.upper().replace('-','_'))

		#sanity check
		if creds.secret_type == [SMBCredentialsSecretType.NT, SMBCredentialsSecretType.RC4]:
			try:
				bytes.fromhex(creds.secret)
				if len(creds.secret) != 32:
					raise Exception()
			except Exception as e:
				raise Exception('This is not a valid NT hash')
				
		elif creds.secret_type == SMBCredentialsSecretType.AES:
			try:
				bytes.fromhex(creds.secret)
				if len(creds.secret) != 32 or len(creds.secret) != 64:
					raise Exception()
			except Exception as e:
				raise Exception('This is not a valid NT hash')
				
		elif creds.secret_type == SMBCredentialsSecretType.CCACHE:
			try:
				with open(creds.secret, 'rb') as f:
					a = 1
			except Exception as e:
				raise Exception('Could not open CCACHE file!')
		
		
		if creds.authentication_type == SMBAuthProtocol.NTLM:
			if creds.secret_type not in [SMBCredentialsSecretType.NT, SMBCredentialsSecretType.RC4, SMBCredentialsSecretType.PASSWORD]:
				raise Exception('NTLM authentication requires either password or NT hash or RC4 key to be specified as secret!')
				
		elif creds.authentication_type == SMBAuthProtocol.KERBEROS:
			if creds.secret_type not in [SMBCredentialsSecretType.NT, SMBCredentialsSecretType.RC4, SMBCredentialsSecretType.PASSWORD, SMBCredentialsSecretType.AES, SMBCredentialsSecretType.CCACHE]:
				raise Exception('KERBEROS authentication requires either password or NT hash or RC4 key or AES key or CCACHE file to be specified as secret!')
		
		elif creds.authentication_type in [SMBAuthProtocol.SSPI_NTLM,  SMBAuthProtocol.SSPI_KERBEROS]:
			if platform.system() != 'Windows':
				raise Exception('SSPI authentication on works on windows!')
		
		return creds
		
class SMBKerberosCredential:
	def __init__(self):
		self.mode = 'CLIENT'
		self.connection = None #KerberosCredential
		self.target = None #KerberosTarget
		self.ksoc = None #KerberosSocketAIO
		self.ccred = None
		
class SMBKerberosSSPICredential:
	def __init__(self):
		self.mode = 'CLIENT'
		self.client = None
		self.password = None
		self.target  = None
		
class SMBNTLMSSPICredential:
	def __init__(self):
		self.mode = 'CLIENT'
		self.client = None
		self.passwrd = None
		
class SMBNTLMCredential:
	def __init__(self):
		self.username = None
		self.domain = ''
		self.password = None
		self.workstation = None
		self.is_guest = False
		self.nt_hash = None
		self.lm_hash = None

class SMBWSNETCredential:
	def __init__(self):
		self.mode = 'CLIENT'
		self.type = 'NTLM'
		self.username = '<CURRENT>'
		self.domain = '<CURRENT>'
		self.password = '<CURRENT>'
		self.target = None
		self.is_guest = False

class SMBSSPIProxyCredential:
	def __init__(self):
		self.mode = 'CLIENT'
		self.type = 'NTLM'
		self.username = '<CURRENT>'
		self.domain = '<CURRENT>'
		self.password = '<CURRENT>'
		self.target = None
		self.is_guest = False
		self.host = '127.0.0.1'
		self.port = 9999
		self.proto = 'ws'
		self.agent_id = None

class SMBMultiplexorCredential:
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

class SMBMPNCredential:
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
		self.mp_port = 9999
		self.mp_username = None
		self.mp_domain = None
		self.mp_password = None
		self.agent_id = None
		self.operator = None
		self.timeout = 5


	def get_url(self):
		url_temp = 'ws://%s:%s'
		if self.is_ssl is True:
			url_temp = 'wss://%s:%s'
		url = url_temp % (self.mp_host, self.mp_port)
		return url

	def parse_settings(self, settings):
		self.mp_host = settings['host'][0]
		if 'port' in settings:
			self.mp_port = settings.get['port'][0]
		if 'user' in settings:
			self.mp_username = settings.get('user')[0]
		if 'domain' in settings:
			self.mp_domain = settings.get('domain')[0]
		if 'password' in settings:
			self.mp_password = settings.get('password')[0]
		self.agent_id = uuid.UUID(settings['agentid'][0])

def test():
	s = 'TEST/victim/ntlm/nt:AAAAAAAA@10.10.10.2:445'
	creds = SMBCredential.from_connection_string(s)
	print(str(creds))
	
	s = 'TEST/victim/sspi@10.10.10.2:445/aaaa'
	creds = SMBCredential.from_connection_string(s)
	
	print(str(creds))
	
if __name__ == '__main__':
	test()