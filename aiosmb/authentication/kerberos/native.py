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

import datetime
import copy

from minikerberos.common import *

from minikerberos.protocol.asn1_structs import AP_REP, EncAPRepPart, EncryptedData, Ticket
#from minikerberos.gssapi.gssapi import get_gssapi
from aiosmb.authentication.kerberos.gssapi import get_gssapi
from aiosmb.commons.connection.proxy import  SMBProxyType
from minikerberos.protocol.structures import ChecksumFlags
from minikerberos.protocol.encryption import Enctype, Key, _enctype_table
from minikerberos.protocol.constants import MESSAGE_TYPE
from minikerberos.aioclient import AIOKerberosClient
from minikerberos.network.aioclientsockssocket import AIOKerberosClientSocksSocket
from minikerberos.common.proxy import KerberosProxy

from aiosmb import logger

class SMBKerberos:
	def __init__(self, settings):
		self.settings = settings
		self.mode = None
		self.ccred = None
		self.target = None
		self.spn = None
		self.kc = None
		
		self.session_key = None
		self.gssapi = None
		self.iterations = 0
		self.etype = None
		self.seq_number = None
		self.from_ccache = False
	
		self.setup()
		
		
	async def sign(self, data, message_no, direction = 'init'):
		return self.gssapi.GSS_GetMIC(data, message_no)	
		
	async def encrypt(self, data, message_no):
		return self.gssapi.GSS_Wrap(data, message_no)
		
	async def decrypt(self, data, message_no, direction='init', auth_data=None):
		return self.gssapi.GSS_Unwrap(data, message_no, direction=direction, auth_data=auth_data)
		
	def setup(self):
		self.mode = self.settings.mode
		self.ccred = self.settings.ccred
		self.spn = self.settings.spn
		self.target = self.settings.target
		
	
	def get_session_key(self):
		return self.session_key.contents

	async def setup_kc(self):
		try:
			if self.target.proxy is None or isinstance(self.target.proxy, KerberosProxy) is True:
				self.kc = AIOKerberosClient(self.ccred, self.target)


			elif self.target.proxy.type in [SMBProxyType.MULTIPLEXOR, SMBProxyType.MULTIPLEXOR_SSL]:
				from aiosmb.network.multiplexornetwork import MultiplexorProxyConnection
				mpc = MultiplexorProxyConnection(self.target) 
				socks_proxy, err = await mpc.connect(is_kerberos = True)
				if err is not None:
					raise err

				self.kc = AIOKerberosClient(self.ccred, socks_proxy)

			else:
				raise Exception('Unknown proxy type %s' % self.target.proxy.type)

			return None, None
		except Exception as e:
			return None, e
		
	
	async def authenticate(self, authData, flags = None, seq_number = 0, is_rpc = False):
		try:
			
			if self.kc is None:
				_, err = await self.setup_kc()
				if err is not None:
					return None, None, err


			if self.iterations == 0:
				try:
					#check TGS first, maybe ccache already has what we need
					for target in self.ccred.ccache.list_targets():
						# just printing this to debug...
						logger.debug('CCACHE target SPN record: %s' % target)
					tgs, encpart, self.session_key = await self.kc.get_TGS(self.spn)
					
					self.from_ccache = True
				except Exception as e:
					# this is normal when no credentials stored in ccache
					#tgt = await self.kc.get_TGT(override_etype=[18])
					tgt = await self.kc.get_TGT()
					tgs, encpart, self.session_key = await self.kc.get_TGS(self.spn)
				
			ap_opts = []
			if is_rpc == True:
				if self.iterations == 0:
					ap_opts.append('mutual-required')
					flags = ChecksumFlags.GSS_C_CONF_FLAG | ChecksumFlags.GSS_C_INTEG_FLAG | ChecksumFlags.GSS_C_SEQUENCE_FLAG|\
							ChecksumFlags.GSS_C_REPLAY_FLAG | ChecksumFlags.GSS_C_MUTUAL_FLAG | ChecksumFlags.GSS_C_DCE_STYLE
					
					if self.from_ccache is False:
						apreq = self.kc.construct_apreq(tgs, encpart, self.session_key, flags = flags, seq_number = seq_number, ap_opts=ap_opts)					
					else:
						apreq = self.kc.construct_apreq_from_ticket(Ticket(tgs['ticket']).dump(), self.session_key, tgs['crealm'], tgs['cname']['name-string'][0], flags = flags, seq_number = seq_number, ap_opts = ap_opts, cb_data = None)
			
					self.iterations += 1
					return apreq, False, None
					
				else:
					#mutual authentication part here
					self.seq_number = seq_number

					aprep = AP_REP.load(authData).native
					cipher = _enctype_table[int(aprep['enc-part']['etype'])]()
					cipher_text = aprep['enc-part']['cipher']
					temp = cipher.decrypt(self.session_key, 12, cipher_text)
					
					enc_part = EncAPRepPart.load(temp).native
					cipher = _enctype_table[int(enc_part['subkey']['keytype'])]()
					
					now = datetime.datetime.now(datetime.timezone.utc)
					apreppart_data = {}
					apreppart_data['cusec'] = now.microsecond
					apreppart_data['ctime'] = now.replace(microsecond=0)
					apreppart_data['seq-number'] = enc_part['seq-number']
					#print('seq %s' % enc_part['seq-number'])
					
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
					
					return token, False, None
			else:
				if self.from_ccache is False:
					apreq = self.kc.construct_apreq(tgs, encpart, self.session_key, flags = flags, seq_number = seq_number, ap_opts=ap_opts)
				else:
					apreq = self.kc.construct_apreq_from_ticket(Ticket(tgs['ticket']).dump(), self.session_key, tgs['crealm'], tgs['cname']['name-string'][0], flags = flags, seq_number = seq_number, ap_opts = ap_opts, cb_data = None)
				return apreq, False, None
		
		except Exception as e:
			return None, None, e