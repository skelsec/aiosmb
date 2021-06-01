# Kudos:
# Parts of this code was inspired by the following project by @rubin_mor
# https://github.com/morRubin/AzureADJoinedMachinePTC
# 

# TODO: code needs cleanup, it is still in beta
# TODO: add integrity checks and check certificate of the server
# TODO: code currently supports RSA+DH+SHA1 , add support for other mechanisms

import os
import base64

from aiosmb.authentication.negoex.protocol.messages import MESSAGE_TYPE, PKU2U_TOKEN_TYPE, generate_verify, generate_initiator_metadata, generate_init_nego, generate_ap_req, negoexts_parse_bytes
from aiosmb.authentication.kerberos.gssapi import get_gssapi
from minikerberos.pkinit import PKINIT


class SPNEGOEXAuthHandlerSettings:
	def __init__(self,pfx12_file, pfx12_file_pass, target, dh_params = None, with_certstrore = False):
		self.pfx12_file = pfx12_file
		self.pfx12_file_pass = pfx12_file_pass
		self.target = target
		self.dh_params = dh_params
		self.with_certstrore = with_certstrore
		if dh_params is None:
			self.dh_params = {
				'p' : int('00ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece65381ffffffffffffffff', 16),
				'g' : 2
			}

class SPNEGOEXAuthHandler:
	def __init__(self, settings):
		self.settings = settings
		self.target = None
		self.pkinit = None
		self.gssapi = None

		self._convid = os.urandom(16)
		self._msgctr = 0
		self._krb_finished_data = b''
		self._msgs = b''
		self.session_key_data = None
		self.xxxxx = None

		self.iteractions = 0

	def setup(self):
		self.target = self.settings.target
		if self.settings.with_certstrore is False:
			self.pkinit = PKINIT.from_pfx(self.settings.pfx12_file, self.settings.pfx12_file_pass, dh_params = self.settings.dh_params)
		else:
			self.pkinit = PKINIT.from_windows_certstore(self.settings.pfx12_file, certstore_name = 'MY', cert_serial = None, dh_params = self.settings.dh_params)
	
	def get_session_key(self):
		return self.session_key.contents

	def __get_metadata(self):
		return generate_initiator_metadata(self._msgctr, self._convid, self.pkinit.get_metadata(target = self.target.get_hostname_or_ip()))
	
	async def sign(self, data, message_no, direction = 'init'):
		return self.gssapi.GSS_GetMIC(data, message_no)	
		
	async def encrypt(self, data, message_no):
		return self.gssapi.GSS_Wrap(data, message_no)
		
	async def decrypt(self, data, message_no, direction='init', auth_data=None):
		return self.gssapi.GSS_Unwrap(data, message_no, direction=direction, auth_data=auth_data)
	
	async def authenticate(self, authData, flags = None, seq_number = 0, is_rpc = False):
		if self.iteractions == 0:
			self.setup()
			self.iteractions += 1
			#authdata should be 0 at this point

			asreq = self.pkinit.build_asreq(target = self.target.get_hostname_or_ip(), kdcopts = ['forwardable','renewable','proxiable', 'canonicalize'])

			negodata = generate_init_nego(self._msgctr, self._convid)
			self._msgctr += 1
			metadata = self.__get_metadata()
			self._msgctr += 1
			ap_req, token_raw = generate_ap_req(self._msgctr, self._convid, asreq, PKU2U_TOKEN_TYPE.KRB_AS_REQ)
			self._krb_finished_data += token_raw # for the checksum calc...
			self._msgctr += 1
			msg = negodata + metadata + ap_req
			self._msgs += msg

			return msg, True, None

		elif self.iteractions == 1:
			from minikerberos.protocol.encryption import Enctype, _checksum_table, _enctype_table, Key
			self.iteractions += 1
			
			self._msgs += authData
			msgs = negoexts_parse_bytes(authData)
			self._msgctr += len(msgs)
			#print(msgs[MESSAGE_TYPE.CHALLENGE].Exchange.inner_token.native)
			as_rep = msgs[MESSAGE_TYPE.CHALLENGE].Exchange.inner_token.native
			self._krb_finished_data += msgs[MESSAGE_TYPE.CHALLENGE].exchange_data_raw # for the checksum calc...
			encasrep, session_key, cipher = self.pkinit.decrypt_asrep(as_rep)

			self.xxxxx = session_key

			self.session_key_data = {}
			self.session_key_data['keytype'] = Enctype.AES256
			self.session_key_data['keyvalue'] = os.urandom(32)
			subkey_cipher = _enctype_table[self.session_key_data['keytype']]
			subkey_key = Key(subkey_cipher.enctype, self.session_key_data['keyvalue'])
			subkey_checksum = _checksum_table[16] # ChecksumTypes.hmac_sha1_96_aes256

			ap_req = self.pkinit.build_apreq(as_rep, session_key, cipher, self.session_key_data, self._krb_finished_data)

			ap_req_msg, _ = generate_ap_req(self._msgctr, self._convid, ap_req, PKU2U_TOKEN_TYPE.KRB_AP_REQ)
			#print(ap_req_msg.hex())
			self._msgctr += 1
			checksum_final = subkey_checksum.checksum(subkey_key, 25, self._msgs + ap_req_msg )
			verify_msg = generate_verify(self._msgctr, self._convid, checksum_final,  16)
			self._msgctr += 1

			ret_msg = ap_req_msg + verify_msg
			self._msgs += ret_msg

			return ret_msg, True, None


		elif self.iteractions == 2:
			from minikerberos.protocol.encryption import Enctype, _checksum_table, _enctype_table, Key
			from minikerberos.protocol.asn1_structs import EncAPRepPart

			#input('aaaaaaaaaaaaaa')
			self.iteractions += 1
			self._msgs += authData
			msgs = negoexts_parse_bytes(authData)
			self._msgctr += len(msgs)
			ap_rep = msgs[MESSAGE_TYPE.CHALLENGE].Exchange.inner_token.native
			#print(ap_rep)

			#self.xxxxx

			cipher = _enctype_table[int(ap_rep['enc-part']['etype'])]()
			cipher_text = ap_rep['enc-part']['cipher']
			subkey_key = Key(cipher.enctype, self.xxxxx.contents)
			temp = cipher.decrypt(subkey_key, 12, cipher_text)
			enc_part = EncAPRepPart.load(temp).native
			#print(enc_part)
			
			cipher = _enctype_table[int(enc_part['subkey']['keytype'])]()
			self.session_key = Key(cipher.enctype, enc_part['subkey']['keyvalue'])
			self.gssapi = get_gssapi(self.session_key)

			return None, False, None

