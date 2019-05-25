import enum
import platform

if platform.system().upper() == 'WINDOWS':
	from aiosmb.kerberos.kerberos_sspi import SMBKerberosSSPI
	from aiosmb.ntlm.ntlm_sspi import SMBNTLMSSPI

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
	SSPI = 'SSPI'


class SMBCredentials:
	def __init__(self):
		self.username = None
		self.domain = None
		self.secret = None
		self.secret_type = None #SMBCredentialsSecretType
		
		self.authentication_type = None #kerberos or NTLM or ...
			
		#domain/user/auth_type/secret_type:secret@target_ip_hostname_fqdn:target_port/dc_ip
	
	@staticmethod
	def from_connection_string(s):
		creds = SMBCredentials()
		
		t, target = s.rsplit('@')
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
		
		elif creds.authentication_type == SMBCredentialsAuthType.SSPI:
			if platform.system() != 'Windows':
				raise Exception('SSPI authentication on works on windows!')
		
		return creds
		
	def to_spnego(self):
		if self.authentication_type == SMBCredentialsAuthType.NTLM:
			credential = Credential()
			credential.username = 'victim'
			credential.password = 'Passw0rd!1'
			credential.domain = 'TEST'
			
			settings = NTLMHandlerSettings(credential, mode = 'CLIENT', template_name = template_name)
			handler = NTLMAUTHHandler(settings)
			
			#setting up SPNEGO
			spneg = SPNEGO()
			spneg.add_auth_context('NTLMSSP - Microsoft NTLM Security Support Provider', handler)
			
		elif self.authentication_type == SMBCredentialsAuthType.KERBEROS:
			settings = {
				'mode' : 'CLIENT',
				'connection_string' : 'TEST/victim/pass:Passw0rd!1@10.10.10.2',
				'target_string': 'cifs/WIN2019AD@TEST.CORP',
				'dc_ip' : '10.10.10.2',
			}
			
			handler = SMBKerberos(settings)
			
			#setting up SPNEGO
			spneg = SPNEGO()
			spneg.add_auth_context('MS KRB5 - Microsoft Kerberos 5', handler)
			
		elif self.authentication_type == SMBCredentialsAuthType.SSPI:
			settings = {
				'mode' : 'CLIENT',
				'username' : None,
				'password' : None,
				'target' : 'WIN2019AD',
			}
			handler = SMBKerberosSSPI(settings)
			#setting up SPNEGO
			spneg = SPNEGO()
			spneg.add_auth_context('MS KRB5 - Microsoft Kerberos 5', handler)
			
			settings = {
				'mode' : 'CLIENT',
			}
			handler = SMBNTLMSSPI(settings)
			#setting up SPNEGO
			spneg = SPNEGO()
			spneg.add_auth_context('NTLMSSP - Microsoft NTLM Security Support Provider', handler)
			
		
		
	def __str__(self):
		t = '==== SMBCredentials ===\r\n'
		for k in self.__dict__:
			t += '%s: %s\r\n' % (k, self.__dict__[k])
			
		return t

def test():
	s = 'TEST/victim/ntlm/nt:AAAAAAAA@10.10.10.2:445'
	creds = SMBCredentials.from_connection_string(s)
	print(str(creds))
	
	s = 'TEST/victim/sspi@10.10.10.2:445/aaaa'
	creds = SMBCredentials.from_connection_string(s)
	
	print(str(creds))
	
if __name__ == '__main__':
	test()
		
"""
python NTLM: plaintext or NT hash
sspi NTLM: none or splintext
python kerberos: plaintext or NT or aeskeys
sspi kerberos: none or plaintext

"""
"""		
class SMBTarget:
	def __init__(self):
		pass
		

class AuthenticatorBuilder:
	def __init__(self):
		pass
		
		
	

	async def test(target):
	#setting up NTLM auth
	template_name = 'Windows10_15063_knowkey'
	credential = Credential()
	credential.username = 'victim'
	credential.password = 'Passw0rd!1'
	credential.domain = 'TEST'
	
	settings = NTLMHandlerSettings(credential, mode = 'CLIENT', template_name = template_name)
	handler = NTLMAUTHHandler(settings)
	
	#setting up SPNEGO
	spneg = SPNEGO()
	spneg.add_auth_context('NTLMSSP - Microsoft NTLM Security Support Provider', handler)
	connection = SMBConnection(spneg, [NegotiateDialects.SMB210])
	
	
	#setting up NTLM auth
	template_name = 'Windows10_15063_knowkey'
	credential = Credential()
	credential.username = 'victim'
	credential.password = 'Passw0rd!1'
	credential.domain = 'TEST'
	
	settings = NTLMHandlerSettings(credential, mode = 'CLIENT', template_name = template_name)
	handler = NTLMAUTHHandler(settings)
	
	#setting up SPNEGO
	spneg = SPNEGO()
	spneg.add_auth_context('NTLMSSP - Microsoft NTLM Security Support Provider', handler)
	
	
	settings = {
		'mode' : 'CLIENT',
		'connection_string' : 'TEST/victim/pass:Passw0rd!1@10.10.10.2',
		'target_string': 'cifs/WIN2019AD@TEST.CORP',
		'dc_ip' : '10.10.10.2',
	}
	
	handler = SMBKerberos(settings)
	
	#setting up SPNEGO
	spneg = SPNEGO()
	spneg.add_auth_context('MS KRB5 - Microsoft Kerberos 5', handler)


	settings = {
		'mode' : 'CLIENT',
		'username' : None,
		'password' : None,
		'target' : 'WIN2019AD',
	}
	handler = SMBKerberosSSPI(settings)
	#setting up SPNEGO
	spneg = SPNEGO()
	spneg.add_auth_context('MS KRB5 - Microsoft Kerberos 5', handler)

	
	settings = {
		'mode' : 'CLIENT',
	}
	handler = SMBNTLMSSPI(settings)
	#setting up SPNEGO
	spneg = SPNEGO()
	spneg.add_auth_context('NTLMSSP - Microsoft NTLM Security Support Provider', handler)

"""
