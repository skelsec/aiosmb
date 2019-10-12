#
#
# This is just a simple interface to the winsspi library to support NTLM
# 

from aiosmb.ntlm.auth_handler import NTLMAUTHHandler, NTLMHandlerSettings
from multiplexor.operator.external.sspi import SSPINTLMClient
from multiplexor.operator import MultiplexorOperator

class SMBNTLMMultiplexor:
	def __init__(self, settings):
		self.settings = settings
		self.mode = None #'CLIENT'
		self.sspi = None
		self.operator = None
		self.client = None
		self.target = None
		#self.ntlmChallenge = None
		
		self.session_key = None
		self.ntlm_ctx = NTLMAUTHHandler(NTLMHandlerSettings(None, 'MANUAL'))

	def setup(self):
		return
		
	@property
	def ntlmChallenge(self):
		return self.ntlm_ctx.ntlmChallenge
		
	def get_sealkey(self, mode = 'Client'):
		return self.ntlm_ctx.get_sealkey(mode = mode)
			
	def get_signkey(self, mode = 'Client'):
		return self.ntlm_ctx.get_signkey(mode = mode)
		
		
	def SEAL(self, signingKey, sealingKey, messageToSign, messageToEncrypt, seqNum, cipher_encrypt):
		return self.ntlm_ctx.SEAL(signingKey, sealingKey, messageToSign, messageToEncrypt, seqNum, cipher_encrypt)
		
	def SIGN(self, signingKey, message, seqNum, cipher_encrypt):
		return self.ntlm_ctx.SIGN(signingKey, message, seqNum, cipher_encrypt)
	
	def get_session_key(self):
		return self.session_key
		
	def get_extra_info(self):
		return self.ntlm_ctx.get_extra_info()
		
	def is_extended_security(self):
		return self.ntlm_ctx.is_extended_security()
		
	async def encrypt(self, data, message_no):
		return self.sspi.encrypt(data, message_no)
		
	async def decrypt(self, data, message_no):
		return self.sspi.decrypt(data, message_no)
	
	async def authenticate(self, authData = None, flags = None, seq_number = 0, is_rpc = False):
		if self.sspi is None:
			await self.start_remote_sspi()
		
		if self.settings.mode == 'CLIENT':
			if authData is None:
				data, res = await self.sspi.authenticate(is_rpc = is_rpc)
				print('authenticatE: %s' % data)
				if res is None:
					self.ntlm_ctx.load_negotiate(data)
				return data, res
			else:
				self.ntlm_ctx.load_challenge( authData)
				data, res = await self.sspi.challenge(authData, is_rpc = is_rpc)
				print('challenge: %s' % data)
				if res is None:
					self.ntlm_ctx.load_authenticate( data)
					self.session_key, res = await self.sspi.get_session_key()
					print('session_key: %s' % self.session_key)
					if res is None:
						self.ntlm_ctx.load_sessionkey(self.get_session_key())
					else:
						print(res)
				
				return data, res
				
		else:
			raise Exception('Server mode not implemented!')


	async def start_remote_sspi(self):
		try:
			print(self.settings.get_url())
			self.operator = MultiplexorOperator(self.settings.get_url())
			await self.operator.connect()
			#creating socks5 proxy
			server_info = await self.operator.start_sspi(self.settings.agent_id)
			#print(server_info)
			#tp.ip = server_info['listen_ip']
			#tp.port = server_info['listen_port']
			#tp.timeout = self.target.proxy.timeout

			sspi_url = 'ws://%s:%s' % (server_info['listen_ip'], server_info['listen_port'])

			print(sspi_url)
			self.sspi = SSPINTLMClient(sspi_url)
			await self.sspi.connect()
		except Exception as e:
			import traceback
			traceback.print_exc()
			return None
			
	