
import os
from aiosmb.ntlm.templates.server import NTLMServerTemplates
from aiosmb.ntlm.templates.client import NTLMClientTemplates
from aiosmb.ntlm.structures.negotiate_flags import NegotiateFlags
from aiosmb.ntlm.structures.version import Version
from aiosmb.ntlm.messages.negotiate import NTLMNegotiate
from aiosmb.ntlm.messages.challenge import NTLMChallenge
from aiosmb.ntlm.messages.authenticate import NTLMAuthenticate
from aiosmb.ntlm.creds_calc import *
from aiosmb.crypto.symmetric import RC4



class Credential:
	def __init__(self):
		self.username = None
		self.domain = ''
		self.password = None
		self.workstation = None
		self.is_guest = False
		self.nt_hash = None
		self.lm_hash = None
		
		
class NTLMHandlerSettings:
	def __init__(self, credential, mode = 'CLIENT', template_name = None, ntlm_downgrade = False, custom_template = None):
		self.credential = credential
		self.mode = mode
		self.template_name = template_name
		self.ntlm_downgrade = ntlm_downgrade
		self.custom_template = custom_template #for custom templates, must be dict
		
		self.template = None
		
		self.construct_message_template()
		
	def construct_message_template(self):
		if not self.template_name:
			if not self.custom_template:
				raise Exception('No NTLM tamplate specified!')
			
			self.template = self.custom_template
		
		else:
			if self.mode.upper() == 'SERVER':
				if self.template_name in NTLMServerTemplates:
					self.template = NTLMServerTemplates[self.template_name]
				else:
					raise Exception('No NTLM server template found with name %s' % self.template_name)
		
			else:
				if self.template_name in NTLMClientTemplates:
					self.template = NTLMClientTemplates[self.template_name]
				else:
					raise Exception('No NTLM server template found with name %s' % self.template_name)
		

class NTLMAUTHHandler:
	def __init__(self, settings):
		self.settings = settings #NTLMHandlerSettings		
		
		self.mode = None
		self.flags = None
		self.challenge = None
		
		self.ntlmNegotiate     = None #ntlm Negotiate message from client
		self.ntlmChallenge     = None #ntlm Challenge message to client
		self.ntlmAuthenticate  = None #ntlm Authenticate message from client

		
		self.EncryptedRandomSessionKey = None
		self.RandomSessionKey = None
		self.SessionBaseKey = None
		self.KeyExchangeKey = None
		
		self.iteration_cnt = 0
		self.ntlm_credentials = None
		self.timestamp = None #used in unittest only!
		self.setup()

	def setup(self):
		if 'challenge' not in self.settings.template:
			self.challenge = os.urandom(8)
		else:
			self.challenge = self.settings.template['challenge']
		self.flags = self.settings.template['flags']
		if 'session_key' in self.settings.template:
			self.RandomSessionKey = self.settings.template['session_key']
		self.mode = self.settings.mode
		self.timestamp = self.settings.template.get('timestamp') #used in unittest only!
		
					
		if self.mode.upper() == 'SERVER':
			version    = self.settings.template['version']
			targetName = self.settings.template['targetname']
			targetInfo = self.settings.template['targetinfo']

			self.ntlmChallenge = NTLMChallenge.construct(challenge = self.challenge_server, targetName = targetName, targetInfo = targetInfo, version = version, flags = self.flags)
		
		else:
			domainname = self.settings.template['domain_name']
			workstationname = self.settings.template['workstation_name']
			version = self.settings.template.get('version')
			self.ntlmNegotiate = NTLMNegotiate.construct(self.flags, domainname = domainname, workstationname = workstationname, version = version)			

	def get_session_key(self):
		return self.RandomSessionKey
		
	def setup_crypto(self):
		if not self.RandomSessionKey:
			self.RandomSessionKey = os.urandom(16)
		
		self.SessionBaseKey = self.ntlm_credentials.SessionBaseKey
		
		rc4 = RC4(self.KeyExchangeKey)
		self.EncryptedRandomSessionKey = rc4.encrypt(self.RandomSessionKey)
		
		#if self.flags & 

	def authenticate(self, authData):
		if self.mode == 'SERVER':
			if self.ntlmNegotiate is None:
				###parse client NTLMNegotiate message
				self.ntlmNegotiate = NTLMNegotiate.from_bytes(authData)
				return self.ntlmChallenge.to_bytes(), True 

			elif self.ntlmAuthenticate is None:
				self.ntlmAuthenticate = NTLMAuthenticate.from_bytes(authData, self.use_NTLMv2)
				creds = NTLMcredential.construct(self.ntlmNegotiate, self.ntlmChallenge, self.ntlmAuthenticate)
				print(creds)

				# TODO: check when is sessionkey needed and check when is singing needed, and calculate the keys!
				# self.calc_SessionBaseKey()
				# self.calc_KeyExchangeKey()
				auth_credential = creds[0]
				#self.SessionBaseKey = auth_credential.calc_session_base_key()
				#self.calc_key_exchange_key()

				if auth_credential.verify(self.credential):
					return AuthResult.FAIL, auth_credential
				else:
					return AuthResult.FAIL, auth_credential

			else:
				raise Exception('Too many calls to do_AUTH function!')
				
		else:
			if self.iteration_cnt == 0:
				if authData is not None:
					raise Exception('First call as client MUST be with empty data!')
				
				self.iteration_cnt += 1
				#negotiate message was already calulcated in setup
				return self.ntlmNegotiate.to_bytes(), True
				
			else:
				#server challenge incoming
				self.ntlmChallenge = NTLMChallenge.from_bytes(authData)
				
				#we need to calculate the response based on the credential and the settings flags
				if self.settings.ntlm_downgrade == True:
					#NTLMv1 authentication
					# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/464551a8-9fc4-428e-b3d3-bc5bfb2e73a5
					
					#check if we authenticate as guest
					if self.settings.credential.is_guest == True:
						lmresp = LMResponse()
						lmresp.Response = b'\x00'
						self.ntlmAuthenticate = NTLMAuthenticate.construct(self.flags, lm_response= lmresp)
						return self.ntlmAuthenticate.to_bytes(), False
						
					if self.flags & NegotiateFlags.NEGOTIATE_EXTENDED_SESSIONSECURITY:
						#Extended auth!
						self.ntlm_credentials = netntlm_ess.construct(self.ntlmChallenge.ServerChallenge, self.challenge, self.settings.credential)
						
						self.KeyExchangeKey = self.ntlm_credentials.calc_key_exchange_key()						
						self.setup_crypto()
						
						self.ntlmAuthenticate = NTLMAuthenticate.construct(self.flags, lm_response= self.ntlm_credentials.LMResponse, nt_response = self.ntlm_credentials.NTResponse, version = self.ntlmNegotiate.Version, encrypted_session = self.EncryptedRandomSessionKey)
					else:
						self.ntlm_credentials = netntlm.construct(self.ntlmChallenge.ServerChallenge, self.settings.credential)
						
						self.KeyExchangeKey = self.ntlm_credentials.calc_key_exchange_key(with_lm = self.flags & NegotiateFlags.NEGOTIATE_LM_KEY, non_nt_session_key = self.flags & NegotiateFlags.REQUEST_NON_NT_SESSION_KEY)						
						self.setup_crypto()
						self.ntlmAuthenticate = NTLMAuthenticate.construct(self.flags, lm_response= self.ntlm_credentials.LMResponse, nt_response = self.ntlm_credentials.NTResponse, version = self.ntlmNegotiate.Version, encrypted_session = self.EncryptedRandomSessionKey)

							
							
				else:
					#NTLMv2
					# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/5e550938-91d4-459f-b67d-75d70009e3f3
					if self.settings.credential.is_guest == True:
						lmresp = LMResponse()
						lmresp.Response = b'\x00'
						self.ntlmAuthenticate = NTLMAuthenticate.construct(self.flags, lm_response= lmresp)
						return self.ntlmAuthenticate.to_bytes(), False
						
					else:
						self.ntlm_credentials = netntlmv2.construct(self.ntlmChallenge.ServerChallenge, self.challenge, self.ntlmChallenge.TargetInfo, self.settings.credential, timestamp = self.timestamp)
						self.KeyExchangeKey = self.ntlm_credentials.calc_key_exchange_key()						
						self.setup_crypto()
						
						self.ntlmAuthenticate = NTLMAuthenticate.construct(self.flags, domainname= self.settings.credential.domain, workstationname= self.settings.credential.workstation, username= self.settings.credential.username, lm_response= self.ntlm_credentials.LMResponse, nt_response= self.ntlm_credentials.NTResponse, version = self.ntlmNegotiate.Version, encrypted_session = self.EncryptedRandomSessionKey)
						
				return self.ntlmAuthenticate.to_bytes(), False

def test_msdn():
	credential = Credential()
	credential.username = 'User'
	credential.domain = 'Domain'
	credential.password = 'Password'
	
	template = {
			'flags'            :  NegotiateFlags.NEGOTIATE_56|
								  NegotiateFlags.REQUEST_NON_NT_SESSION_KEY|
								  NegotiateFlags.NEGOTIATE_KEY_EXCH|
								  NegotiateFlags.NEGOTIATE_128|
								  NegotiateFlags.NEGOTIATE_VERSION|
								  NegotiateFlags.TARGET_TYPE_SERVER|
								  NegotiateFlags.NEGOTIATE_ALWAYS_SIGN|
								  NegotiateFlags.NEGOTIATE_NTLM|
								  NegotiateFlags.NEGOTIATE_SIGN|
								  NegotiateFlags.NEGOTIATE_SEAL|
								  NegotiateFlags.NTLM_NEGOTIATE_OEM|
								  NegotiateFlags.NEGOTIATE_UNICODE,
			'version'          : Version.construct(WindowsMajorVersion.WINDOWS_MAJOR_VERSION_10, minor = WindowsMinorVersion.WINDOWS_MINOR_VERSION_0, build = 15063 ),
			'domain_name'      : 'Domain',
			'workstation_name' : 'COMPUTER',
			'ntlm_downgrade'   : True,
			'extended_security': False
	}
	settings = NTLMHandlerSettings(credential, mode = 'CLIENT', template_name = None, ntlm_downgrade = True, extended_security = False, custom_template = template)
	handler = NTLMAUTHHandler(settings)
	#assert handler.flags == int.from_bytes(b'\x33\x82\x02\xe2', "little", signed = False)
	data, is_res = handler.authenticate(None)
	print(data)
	print(is_res)
	
	details = AVPairs({AVPAIRType.MsvAvNbDomainName: 'TEST', AVPAIRType.MsvAvNbComputerName: 'WIN2019AD', AVPAIRType.MsvAvDnsDomainName: 'test.corp', AVPAIRType.MsvAvDnsComputerName: 'WIN2019AD.test.corp', AVPAIRType.MsvAvTimestamp: b'\xae\xc6\x00\xbf\xc5\xfd\xd4\x01', AVPAIRType.MsvAvFlags: b'\x02\x00\x00\x00', AVPAIRType.MsvAvSingleHost: b"0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00 \x00\x00R}'\xf24\xdet7`\x96c\x84\xd3oa\xae*\xa4\xfc*8\x06\x99\xf8\xca\xa6\x00\x01\x1bHm\x89", AVPAIRType.MsvChannelBindings: b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', AVPAIRType.MsvAvTargetName: 'cifs/10.10.10.2'})
	
	challenge = NTLMChallenge.construct(challenge=b'\x01\x23\x45\x67\x89\xab\xcd\xef', targetName = 'Domain', targetInfo = details, version = handler.ntlmNegotiate.Version, flags= handler.flags)
	data, is_res = handler.authenticate(challenge.to_bytes())
	print(data)
	print(is_res)
	
	print(handler.ntlmAuthenticate.LMChallenge.to_bytes().hex())
	print(handler.ntlmAuthenticate.NTChallenge.to_bytes().hex())
	

def test():
	template_name = 'Windows10_15063'
	credential = Credential()
	credential.username = 'test'
	credential.password = 'test'
	
	settings = NTLMHandlerSettings(credential, mode = 'CLIENT', template_name = template_name, ntlm_downgrade = False, extended_security = True)
	handler = NTLMAUTHHandler(settings)
	data, is_res = handler.authenticate(None)
	print(data)
	print(is_res)
	
if __name__ == '__main__':
	from aiosmb.ntlm.structures.version import Version, WindowsMajorVersion, WindowsMinorVersion
	test_msdn()