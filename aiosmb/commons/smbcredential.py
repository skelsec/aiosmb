import enum
import platform

class SMBCredentialsSecretType(enum.Enum):
	NT = 'NT'
	PASSWORD = 'PASSWORD'
	AES = 'AES'
	RC4 = 'RC4'
	CCACHE = 'CCACHE'
	NONE = 'NONE'
	
	
class SMBCredentialsAuthType(enum.Enum):
	NTLM = 'NTLM'
	KERBEROS = 'KERBEROS'
	SSPI_KERBEROS = 'SSPI-KERBEROS'
	SSPI_NTLM = 'SSPI-NTLM'


class SMBCredential:
	def __init__(self):
		self.username = None
		self.domain = None
		self.secret = None
		self.secret_type = None #SMBCredentialsSecretType
		
		self.authentication_type = None #kerberos or NTLM or ...
			
		#domain/user/auth_type/secret_type:secret@target_ip_hostname_fqdn:target_port/dc_ip
	
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
		creds.authentication_type = SMBCredentialsAuthType(auth_type.upper())
		
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
		
		
		if creds.authentication_type == SMBCredentialsAuthType.NTLM:
			if creds.secret_type not in [SMBCredentialsSecretType.NT, SMBCredentialsSecretType.RC4, SMBCredentialsSecretType.PASSWORD]:
				raise Exception('NTLM authentication requires either password or NT hash or RC4 key to be specified as secret!')
				
		elif creds.authentication_type == SMBCredentialsAuthType.KERBEROS:
			if creds.secret_type not in [SMBCredentialsSecretType.NT, SMBCredentialsSecretType.RC4, SMBCredentialsSecretType.PASSWORD, SMBCredentialsSecretType.AES, SMBCredentialsSecretType.CCACHE]:
				raise Exception('KERBEROS authentication requires either password or NT hash or RC4 key or AES key or CCACHE file to be specified as secret!')
		
		elif creds.authentication_type in [SMBCredentialsAuthType.SSPI_NTLM,  SMBCredentialsAuthType.SSPI_KERBEROS]:
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
		
def test():
	s = 'TEST/victim/ntlm/nt:AAAAAAAA@10.10.10.2:445'
	creds = SMBCredential.from_connection_string(s)
	print(str(creds))
	
	s = 'TEST/victim/sspi@10.10.10.2:445/aaaa'
	creds = SMBCredential.from_connection_string(s)
	
	print(str(creds))
	
if __name__ == '__main__':
	test()