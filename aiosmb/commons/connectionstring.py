import enum
from urllib.parse import urlparse, parse_qs
from aiosmb.commons.smbcredential import SMBCredential
from aiosmb.commons.smbtargetproxy import SMBTargetProxy

class SMBConnectionDialect(enum.Enum):
	SMB = 'SMB' #any

class SMBConnectionProtocol(enum.Enum):
	TCP = 'TCP'
	UDP = 'UDP'

class SMBAuthProtocol(enum.Enum):
	NTLM = 'NTLM'
	KERBEROS = 'KERBEROS'
	SSPI_KERBEROS = 'SSPI_KERBEROS'
	SSPI_NTLM = 'SSPI_NTLM'
	MULTIPLEXOR_NTLM = 'MULTIPLEXOR_NTLM'
	MULTIPLEXOR_KERBEROS = 'MULTIPLEXOR_KERBEROS'

class SMBCredentialSecretType(enum.Enum):
	NT = 'NT'
	PASSWORD = 'PASSWORD'
	AES = 'AES'
	RC4 = 'RC4'
	CCACHE = 'CCACHE'
	NONE = 'NONE'

class SMBProxyType:
	SOCKS5 = 'SOCKS5'
	MULTIPLEXOR = 'MULTIPLEXOR'

class SMBProxyAuthProtocol:
	NONE = 'NONE'
	PLAIN = 'PLAIN'

"""
class SMBCredentialsAuthType(enum.Enum):
	NTLM = 'NTLM'
	KERBEROS = 'KERBEROS'
	SSPI_KERBEROS = 'SSPI-KERBEROS'
	SSPI_NTLM = 'SSPI-NTLM'
	MULTIPLEXOR = 'MULTIPLEXOR'

class SMBTargetProxySecretType(enum.Enum):
	NONE = 'NONE'
	PLAIN = 'PLAIN'

class SMBTargetProxyServerType(enum.Enum):
	SOCKS5 = 'SOCKS5'
	SOCKS5_SSL = 'SOCKS5_SSL'
	MULTIPLEXOR = 'MULTIPLEXOR'
	MULTIPLEXOR_SSL = 'MULTIPLEXOR_SSL'
"""

class SMBConnectionString:
	def __init__(self, connection_string):
		self.connection_string = connection_string
		
		#credential
		self.authentication_protocol = None
		self.secret_type = None
		self.domain = None
		self.username = None
		self.secret = None
		self.is_anonymous = None
		self.auth_settings = {}

		#target
		self.dialect = None
		self.protocol = None
		self.hostname = None
		self.dc_ip = None
		self.port = None

		#proxy
		self.proxy_type = None
		self.proxy_auth_type = None
		self.proxy_ip = None
		self.proxy_port = None
		self.proxy_user = None
		self.proxy_domain = None
		self.proxy_secret = None
		self.proxy_secret_type = None
		self.proxy_timeout = None
		self.proxy_settings = {}

	def get_proxy(self):
		if self.proxy_type is not None:
			return SMBTargetProxy(
				ip = self.proxy_ip,
				port = self.proxy_port,
				timeout = self.proxy_timeout,
				proxy_type = self.proxy_type,
				username = self.proxy_user,
				domain = self.proxy_domain,
				secret = self.proxy_secret,
				secret_type = self.proxy_secret_type,
				agent_id = None #used by multiplexor only
			)
		return None

	#def get_target(self):
		

	
	def get_credential(self):
		return SMBCredential(
			username = self.username,
			domain = self.domain, 
			secret = self.secret, 
			secret_type = self.secret_type, 
			authentication_type = self.authentication_protocol, 
			settings = self.auth_settings
		)
	

	def scheme_decoder(self, scheme):
		schemes = scheme.upper().split('+')
		
		connection_tags = schemes[0].split('-')
		if len(connection_tags) > 1:
			self.dialect = SMBConnectionDialect(connection_tags[0])
			self.protocol = SMBConnectionProtocol(connection_tags[1])
		else:
			self.dialect = SMBConnectionDialect(connection_tags[0])
			self.protocol = SMBConnectionProtocol.TCP

		if len(schemes) == 1:
			return

		auth_tags = schemes[1].split('-')
		if len(auth_tags) > 1:
			self.authentication_protocol = SMBAuthProtocol(auth_tags[0])
			self.secret_type = SMBCredentialSecretType(auth_tags[1])
		else:
			self.authentication_protocol = SMBAuthProtocol(auth_tags[0])
			if self.authentication_protocol == SMBAuthProtocol.KERBEROS:
				raise Exception('For kerberos auth you need to specify the secret type in the connection string!')
			#secret type will be automatically selected in this case by processing the secret itself #self.secret_type =
		
		#if len(schemes) == 2:
		#	return
		#
		##proxy settings
		#proxy_tags = schemes[2].split('-')
		#if len(proxy_tags) > 1:
		#	self.proxy_type = SMBProxyType(proxy_tags[0])
		#	self.proxy_auth_type = SMBProxyAuthProtocol(proxy_tags[1])
		#else:
		#	self.proxy_type = SMBProxyType(proxy_tags[0])




	def parse(self):
		url_e = urlparse(self.connection_string)
		self.scheme_decoder(url_e.scheme)
		
		if url_e.username is not None:
			if url_e.username.find('\\') != -1:
				self.domain , self.username = url_e.username.split('\\')
			else:
				self.domain = None
				self.username = url_e.username
		
		self.secret = url_e.password
		if self.secret is None and self.username is None:
			self.is_anonymous = True
		
		if self.authentication_protocol == SMBAuthProtocol.NTLM and self.secret_type is None:
			if self.is_anonymous == True:
				self.secret_type = SMBCredentialSecretType.NONE
			else:
				if len(self.secret) == 32:
					try:
						bytes.fromhex(self.secret)
					except:
						self.secret_type = SMBCredentialSecretType.NT
					else:
						self.secret_type = SMBCredentialSecretType.PASSWORD

		elif self.authentication_protocol in [SMBAuthProtocol.SSPI_KERBEROS, SMBAuthProtocol.SSPI_NTLM, 
												SMBAuthProtocol.MULTIPLEXOR_NTLM, SMBAuthProtocol.MULTIPLEXOR_KERBEROS]:
			if self.username is None:
				self.username = '<CURRENT>'
			if self.domain is None:
				self.domain = '<CURRENT>'
			if self.secret is None:
				self.secret = '<CURRENT>'

		# recognized parameters :
		# dc -> domain controller IP
		# proxytype -> proxy protocol
		# proxyuser -> username for proxy auth
		# proxypass -> password for proxy auth
		#  
		#
		if url_e.query is not None:
			query = parse_qs(url_e.query)
			for k in query:
				if k == 'dc':
					self.dc_ip = query[k][0]
				if k == 'dns':
					self.dns = query[k] #multiple dns can be set, so not trimming here
				if k.startswith('proxy'):
					if k == 'proxytype':
						self.proxy_type = SMBProxyType(query[k][0].upper())
					elif k == 'proxyuser':
						self.proxy_username = query[k][0]
					elif k == 'proxypass':
						self.proxy_password = query[k][0]
					else:
						self.proxy_settings[k[len('proxy'):]] = query[k] #the result is a list for each entry because this preprocessor is not aware which elements should be lists!
				

"""
smb-tcp+ntlm-nt+socks://
smb-tcp+ntlm-password
smb://admin:admin@10.10.10.2 <- choose dialect, choose auth protocol, we have password and address but no port
smb-udp
smb-

dialect-protocol+authmethod-secrettype+proxy://domain\\user:password@ip:port/?dc=<ip of the DC>
"""	
			
if __name__ == '__main__':
	url_tests = [
		'smb://10.10.10.2',
		'smb://10.10.10.2:9000',
		'smb-tcp://10.10.10.2',
		'smb-tcp://10.10.10.2:9000',
		'smb-udp://10.10.10.2:138',
		'smb+ntlm-password://domain\\user@10.10.10.2',
		'smb-tcp+ntlm-password://domain\\user:password@10.10.10.2',
		'smb-tcp+ntlm-password://domain\\user:password@10.10.10.2:10000',
		'smb-tcp+ntlm-nt://domain\\user:alma@10.10.10.2',
		'smb+ntlm-nt://domain\\user:alma@10.10.10.2',
		'smb+ntlm-nt://domain\\user:alma@10.10.10.2',
		'smb-tcp+kerberos-password://domain\\alma:password@10.10.10.10.2',
		'smb-tcp+kerberos-aes://domain\\alma:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@10.10.10.10.2',
		'smb-tcp+kerberos-aes://domain\\alma:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@10.10.10.10.2',
		'smb-tcp+kerberos-nt://domain\\alma:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@10.10.10.10.2',
		'smb-tcp+kerberos-rc4://domain\\alma:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@10.10.10.10.2',
		'smb+sspi://10.10.10.10.2',
		'smb+sspi-ntlm://10.10.10.10.2',
		'smb+sspi-kerberos://10.10.10.10.2',
		'smb+multiplexor://10.10.10.10.2',

	]
	for url in url_tests:
		print('===========================================================================')
		print(url)
		try:
			dec = SMBConnectionString(url)
			creds = dec.get_credential()
			#target = dec.get_target()
		except Exception as e:
			import traceback
			traceback.print_exc()
			print('ERROR! Reason: %s' % e)
			input()
		else:
			print(str(creds))
			#print(str(target))
			input()
			
			
