#
#
# This is just a simple interface to the minikerberos library to support SPNEGO
# 
#
# - Hardships - 
# 1. DCERPC kerberos authentication requires a complete different approach and flags,
#    also requires mutual authentication
#
# - Links - 
# 1. Most of the idea was taken from impacket
# 2. See minikerberos library

from minikerberos.common import *
from minikerberos.aiocommunication import *
from minikerberos.gssapi import get_gssapi
from minikerberos.encryption import Enctype, Key, _enctype_table

# SMBKerberosCredential

class SMBKerberos:
	def __init__(self, settings):
		self.settings = settings
		self.mode = None
		self.ccred = None
		self.ksoc = None
		self.target = None
		self.kc = None
		
		self.session_key = None
		self.gssapi = None
		self.iterations = 0
		self.etype = None
	
		self.setup()
		
		
	async def sign(self, data, message_no, direction = 'init'):
		return self.gssapi.GSS_GetMIC(data, message_no, direction = direction)	
		
	async def encrypt(self, data, message_no):
		return self.gssapi.GSS_Wrap(data, message_no)
		
	async def decrypt(self, data, message_no, direction='init', auth_data=None):
		return self.gssapi.GSS_Unwrap(data, message_no, direction=direction, auth_data=auth_data)
		
	def setup(self):
		self.mode = self.settings.mode
		self.ccred = self.settings.ccred
		self.ksoc = self.settings.ksoc
		self.target = self.settings.target
		
		self.kc = KerbrosCommAIO(self.ccred, self.ksoc)
		
	
	def get_session_key(self):
		return self.session_key.contents
	
	async def authenticate(self, authData, flags = None, seq_number = 0, is_rpc = False):
		if self.iterations == 0:
			#tgt = await self.kc.get_TGT(override_etype=[18])
			tgt = await self.kc.get_TGT()
			tgs, encpart, self.session_key = await self.kc.get_TGS(self.target)
		ap_opts = []
		if is_rpc == True:
			if self.iterations == 0:
				ap_opts.append('mutual-required')
				flags = ChecksumFlags.GSS_C_CONF_FLAG | ChecksumFlags.GSS_C_INTEG_FLAG | ChecksumFlags.GSS_C_SEQUENCE_FLAG|\
						ChecksumFlags.GSS_C_REPLAY_FLAG | ChecksumFlags.GSS_C_MUTUAL_FLAG | ChecksumFlags.GSS_C_DCE_STYLE
						
				apreq = self.kc.construct_apreq(tgs, encpart, self.session_key, flags = flags, seq_number = seq_number, ap_opts=ap_opts)					
				self.iterations += 1
				return apreq, False
				
			else:
				#mutual authentication part here
				aprep = AP_REP.load(authData).native
				cipher = _enctype_table[int(aprep['enc-part']['etype'])]()
				cipher_text = aprep['enc-part']['cipher']
				temp = cipher.decrypt(self.session_key, 12, cipher_text)
				
				enc_part = EncAPRepPart.load(temp).native
				cipher = _enctype_table[int(enc_part['subkey']['keytype'])]()
				
				now = datetime.datetime.utcnow() 
				apreppart_data = {}
				apreppart_data['cusec'] = now.microsecond
				apreppart_data['ctime'] = now
				apreppart_data['seq-number'] = enc_part['seq-number']
				
				apreppart_data_enc = cipher.encrypt(self.session_key, 12, EncAPRepPart(apreppart_data).dump(), None)
				
				#overriding current session key
				self.session_key = Key(cipher.enctype, enc_part['subkey']['keyvalue'])
				
				ap_rep = {}
				ap_rep['pvno'] = 5 
				ap_rep['msg-type'] = MESSAGE_TYPE.KRB_AP_REP.value
				ap_rep['enc-part'] = EncryptedData({'etype': self.session_key.enctype, 'cipher': apreppart_data_enc}) 
				
				token = AP_REP(ap_rep).dump()
				
				self.gssapi = get_gssapi(self.session_key)
				self.iterations += 1
				
				return token, False
		else:
			apreq = self.kc.construct_apreq(tgs, encpart, self.session_key, flags = flags, seq_number = seq_number, ap_opts=ap_opts)
			return apreq, False