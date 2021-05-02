from oscrypto.keys import parse_pkcs12
from oscrypto.asymmetric import generate_dh_parameters, dump_dh_parameters, load_private_key
from asn1crypto import core
from asn1crypto.algos import DHParameters
from asn1crypto.keys import DomainParameters, PublicKeyAlgorithm
from asn1crypto.keys import PublicKeyInfo as SubjectPublicKeyInfo
from aiosmb.authentication.negoex.protocol.messages import KDCDHKeyInfo, PA_PK_AS_REP, MESSAGE_TYPE, PKAuthenticator, AuthPack, generate_initiator_metadata, MetaData, generate_init_nego, generate_ap_req, PA_PK_AS_REQ, negoexts_parse_bytes

from minikerberos.protocol.asn1_structs import AS_REQ
from minikerberos.protocol.constants import PaDataType

import hashlib
import base64
import datetime
import secrets
import os

#test
from pprint import pprint


def length_encode(x):
	if x <= 127:
		return x.to_bytes(1, 'big', signed = False)
	else:
		lb = x.to_bytes((x.bit_length() + 7) // 8, 'big')
		t = (0x80 | len(lb)).to_bytes(1, 'big', signed = False)
		return t+lb

class DirtyDH:
	def __init__(self):
		self.p = None
		self.g = None
		self.shared_key = None
		self.shared_key_int = None
		self.private_key = os.urandom(32)
		self.private_key_int = 72764112906046569742760636444493855740760078688881228462873371941677061278611526803054381818644875855167728826228101883887156340871682136831219750416559998567227805189452500583766686867519278844232674078694746027698814055934919355140771557475235517269506974933883648359785247983328280419492831553995014146106
		#int(self.private_key.hex(), 16)
	
	@staticmethod
	def from_params(p, g):
		dd = DirtyDH()
		dd.p = p
		dd.g = g
		return dd

	@staticmethod
	def from_dict(dhp):
		input(1)
		dd = DirtyDH()
		dd.p = int('00ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece65381ffffffffffffffff', 16)  # safe prime
		dd.g = 2
		#dd.p = dhp['p']
		#dd.g = dhp['g']
		return dd

	@staticmethod
	def from_asn1(asn1_bytes):
		dhp = DHParameters.load(asn1_bytes).native
		return DirtyDH.from_dict(dhp)
		
	
	def get_public_key(self):
		#y = g^x mod p
		return pow(self.g, self.private_key_int, self.p)
	
	def exchange(self, bob_int):
		self.shared_key_int = pow(bob_int, self.private_key_int, self.p)
		x = hex(self.shared_key_int)[2:]
		if len(x) % 2 != 0:
			x = '0' + x
		self.shared_key = bytes.fromhex(x)
		return self.shared_key


class SPNEGOEXAuthHandlerSettings:
	def __init__(self,pfx12_file, pfx12_file_pass, target, dh_params = None):
		self.pfx12_file = pfx12_file
		self.pfx12_file_pass = pfx12_file_pass
		self.target = target
		self.dh_params = dh_params
		if dh_params is None:
			self.dh_params = base64.b64decode('MIGHAoGBALZQXoLnJYxi8CqpXEtKBiTu3w84JhaJSmZ1OsLUz8gfj/mOa/kBM5hZbp1bOBkcZCsjEvranNi55rivf7NkEo+XthAWQO/dkxqvxMcSX7mkOhYuG1p7+Yc7J+0hctgkLbrfjG4Cf+RsPDpWC/YQ+qQafgcjBVLuCWGrm/mMBMBzAgEC')
		print(self.dh_params)

class SPNEGOEXAuthHandler:
	def __init__(self, settings):
		self.settings = settings #NTLMHandlerSettings
		self.target = None
		self.privkeyinfo = None
		self.privkey = None
		self.certificate = None
		self.extra_certs = None
		self.issuer = None
		self.user_sid = None
		self.user_name = None
		self.cname = None
		self.diffie = None
		self.dh_nonce = bytes.fromhex('6B328FA66EEBDFD3D69ED34E5007776AB30832A2ED1DCB1699781BFE0BEDF87A')#os.urandom(32)
		self._convid = os.urandom(16)
		self._msgctr = 0


		self.iteractions = 0

	def setup(self):
		self.target = self.settings.target
		print('Loading pfx12')		
		certpass = self.settings.pfx12_file_pass
		if isinstance(certpass, str):
			certpass = certpass.encode()
		with open(self.settings.pfx12_file, 'rb') as f:
			self.privkeyinfo, self.certificate, self.extra_certs = parse_pkcs12(f.read(), password = certpass)
			self.privkey = load_private_key(self.privkeyinfo)
		print('pfx12 loaded!')

		# parsing ceritficate to get basic info that will be needed to construct the asreq
		# this has two components
		for x in self.certificate.subject.native['common_name']:
			if x.startswith("S-1-12"):
				self.user_sid = x
			elif x.find('@') != -1:
				self.user_name = x

		self.issuer = self.certificate.issuer.native['common_name']
		self.cname = '\\'.join(['AzureAD', self.issuer, self.user_sid])

		print('cert issuer: %s' % self.issuer)
		print('cert user_name: %s' % self.user_name)
		print('cert user_sid: %s' % self.user_sid)
		print('cert cname: %s' % self.cname)

		if self.settings.dh_params is None:
			print('Generating DH params...')
			self.diffie = DirtyDH.from_dict( generate_dh_parameters(1024).native)
			print('DH params generated.')
		else:
			print('Loading default DH params...')
			self.diffie = DirtyDH.from_asn1(self.settings.dh_params)
			print('DH params loaded.')

		return
	
	def get_session_key(self):
		raise NotImplementedError()
		#return self.session_key.contents

	def __build_asreq(self):
		import datetime
		import secrets
		from minikerberos.protocol.asn1_structs import KDC_REQ_BODY, PrincipalName, HostAddress, KDCOptions
		from minikerberos.protocol.constants import NAME_TYPE

		now = datetime.datetime.now(datetime.timezone.utc)

		kdc_req_body = {}
		kdc_req_body['kdc-options'] = KDCOptions(set(['forwardable','renewable','proxiable', 'canonicalize']))
		kdc_req_body['cname'] = PrincipalName({'name-type': NAME_TYPE.MS_PRINCIPAL.value, 'name-string': [self.cname]})
		kdc_req_body['realm'] = 'WELLKNOWN:PKU2U'
		kdc_req_body['sname'] = PrincipalName({'name-type': NAME_TYPE.MS_PRINCIPAL.value, 'name-string': [self.target.get_hostname_or_ip()]})
		kdc_req_body['till'] = (now + datetime.timedelta(days=1)).replace(microsecond=0)
		kdc_req_body['rtime'] = (now + datetime.timedelta(days=1)).replace(microsecond=0)
		kdc_req_body['nonce'] = secrets.randbits(31)
		kdc_req_body['etype'] = [18,17,23]
		kdc_req_body['addresses'] = [HostAddress({'addr-type': 20, 'address': b'127.0.0.1'})] # not sure if this is needed
		return KDC_REQ_BODY(kdc_req_body)
		

	
	def sign_msg(self, data, wrap_signed = False):
		"""
		Creating PKCS7 blob which contains the following things:

		1. 'data' blob which is an ASN1 encoded "AuthPack" structure
		2. the certificate used to sign the data blob
		3. the singed 'signed_attrs' structure (ASN1) which points to the "data" structure (in point 1)
		"""
		
		import hashlib
		from oscrypto.keys import parse_pkcs12
		from oscrypto.asymmetric import rsa_pkcs1v15_sign, load_private_key
		from asn1crypto import cms
		from asn1crypto import algos
		from asn1crypto import core
		from asn1crypto import x509
		

		da = {}
		da['algorithm'] = algos.DigestAlgorithmId('1.3.14.3.2.26') # for sha1

		si = {}
		si['version'] = 'v1'
		si['sid'] = cms.IssuerAndSerialNumber({
			'issuer':  self.certificate.issuer,
			'serial_number':  self.certificate.serial_number,
		})


		si['digest_algorithm'] = algos.DigestAlgorithm(da)
		si['signed_attrs'] = [
			cms.CMSAttribute({'type': 'content_type', 'values': ['1.3.6.1.5.2.3.1']}), # indicates that the encap_content_info's authdata struct (marked with OID '1.3.6.1.5.2.3.1' is signed )
			cms.CMSAttribute({'type': 'message_digest', 'values': [hashlib.sha1(data).digest()]}), ### hash of the data, the data itself will not be signed, but this block of data will be.
		]
		si['signature_algorithm'] = algos.SignedDigestAlgorithm({'algorithm' : '1.2.840.113549.1.1.1'})
		si['signature'] = rsa_pkcs1v15_sign(self.privkey,  cms.CMSAttributes(si['signed_attrs']).dump(), "sha1")

		ec = {}
		ec['content_type'] = '1.3.6.1.5.2.3.1'
		ec['content'] = data

		sd = {}
		sd['version'] = 'v3'
		sd['digest_algorithms'] = [algos.DigestAlgorithm(da)] # must have only one
		sd['encap_content_info'] = cms.EncapsulatedContentInfo(ec)
		sd['certificates'] = [self.certificate]
		sd['signer_infos'] = cms.SignerInfos([cms.SignerInfo(si)])
		
		if wrap_signed is True:
			ci = {}
			ci['content_type'] = '1.2.840.113549.1.7.2' # signed data OID
			ci['content'] = cms.SignedData(sd)
			return cms.ContentInfo(ci).dump()

		return cms.SignedData(sd).dump()
		

	def __build_pkinit_pa(self, kdc_req_body):

		now = datetime.datetime.now(datetime.timezone.utc)
		checksum = hashlib.sha1(kdc_req_body.dump()).digest()
		
		authenticator = {}
		authenticator['cusec'] = now.microsecond
		authenticator['ctime'] = now.replace(microsecond=0)
		authenticator['nonce'] = secrets.randbits(31)
		authenticator['paChecksum'] = checksum
		

		dp = {}
		dp['p'] = self.diffie.p
		dp['g'] = self.diffie.g
		dp['q'] = 89884656743115795385419578396893726598930148024378005853222211842098590108079259684473916897932462770751090282742990251823220274099619550025396438501677908319614776568119538254367879957411287431287503712651038723856294775478968889212221213308667363814649693834354602803025135405421453846466009564097233813503
		
		pka = {}
		pka['algorithm'] = '1.2.840.10046.2.1'
		pka['parameters'] = DomainParameters(dp)
		
		spki = {}
		spki['algorithm'] = PublicKeyAlgorithm(pka)
		spki['public_key'] = self.diffie.get_public_key()

		
		authpack = {}
		authpack['pkAuthenticator'] = PKAuthenticator(authenticator)
		authpack['clientPublicValue'] = SubjectPublicKeyInfo(spki)
		authpack['clientDHNonce'] = self.dh_nonce
		
		authpack = AuthPack(authpack)
		signed_authpack = self.sign_msg(authpack.dump(), wrap_signed = False)
		
		# ??????? This is absolutely nonsense, 
		payload = length_encode(len(signed_authpack)) + signed_authpack
		payload = b'\x80' + payload
		signed_authpack = b'\x30' + length_encode(len(payload)) + payload
		
		pa_data_1 = {}
		pa_data_1['padata-type'] = PaDataType.PK_AS_REQ.value
		pa_data_1['padata-value'] = signed_authpack #PA_PK_AS_REQ(pkasreq).dump()
		#input(PA_PK_AS_REQ.load(pa_data_1['padata-value']).native)

		asreq = {}
		asreq['pvno'] = 5
		asreq['msg-type'] = 10
		asreq['padata'] = [pa_data_1]
		asreq['req-body'] = kdc_req_body

		return AS_REQ(asreq).dump()

	def __get_metadata(self):
		from minikerberos.protocol.constants import NAME_TYPE
		from minikerberos.protocol.asn1_structs import PrincipalName
		from aiosmb.authentication.negoex.protocol.messages import Dunno1, Dunno2, Info, CertIssuer, NameTypeAndValueBMP
		
		ci = {}
		ci['type'] = '2.5.4.3'
		ci['value'] = self.issuer

		a = Dunno1([ci])
		ci = Dunno2([a])

		info = {}
		info['pku2u'] = 'WELLKNOWN:PKU2U'
		info['clientInfo'] = PrincipalName({'name-type': NAME_TYPE.MS_PRINCIPAL.value, 'name-string': [str(self.target.get_hostname_or_ip())]})

		md = {}
		md['Info'] = Info(info)
		md['1'] = [CertIssuer({'data' : ci.dump()})]

		metadata = MetaData(md).dump()

		return generate_initiator_metadata(self._msgctr, self._convid, metadata)
	
	def __decrypt_pk_dh(self, as_rep):
		from asn1crypto import cms
		from asn1crypto import algos
		from asn1crypto import core
		from asn1crypto import x509
		from minikerberos.protocol.encryption import Enctype, Key, _enctype_table
		from minikerberos.protocol.asn1_structs import EncASRepPart

		
		def truncate_key(value, keysize):
			output = b''
			currentNum = 0
			while len(output) < keysize:
				currentDigest = hashlib.sha1(bytes([currentNum]) + value).digest()
				if len(output) + len(currentDigest) > keysize:
					output += currentDigest[:keysize - len(output)]
					break
				output += currentDigest
				currentNum += 1
			
			return output

		for pa in as_rep['padata']:
			if pa['padata-type'] == 17:
				pkasrep = PA_PK_AS_REP.load(pa['padata-value']).native
				break
		else:
			raise Exception('PA_PK_AS_REP not found!')
		
		input(as_rep)

		sd = cms.SignedData.load(pkasrep['dhSignedData']).native
		keyinfo = sd['encap_content_info']
		if keyinfo['content_type'] != '1.3.6.1.5.2.3.2':
			raise Exception('Keyinfo content type unexpected value')
		authdata = KDCDHKeyInfo.load(keyinfo['content']).native
		pubkey = int(''.join(['1'] + [str(x) for x in authdata['subjectPublicKey']]), 2)		
		#print('pubkey_hex %s' % core.BitString(authdata['subjectPublicKey']).dump()[7:].hex())
		pubkey = int.from_bytes(core.BitString(authdata['subjectPublicKey']).dump()[7:], 'big', signed = False)
		#print('pubkey %s' % pubkey)
		shared_key = self.diffie.exchange(pubkey)
		#print(shared_key)
		
		server_nonce = pkasrep['serverDHNonce']
		#input('server_nonce \r\n%s' % pkasrep['serverDHNonce'].hex())
		fullKey = shared_key + self.dh_nonce + server_nonce

		etype = as_rep['enc-part']['etype']
		print(etype)
		cipher = _enctype_table[etype]
		if etype == Enctype.AES256:
			t_key = truncate_key(fullKey, 32)
		elif etype == Enctype.AES128:
			t_key = truncate_key(fullKey, 16)
		elif etype == Enctype.RC4:
			t_key = truncate_key(fullKey, 16)
		

		key = Key(cipher.enctype, t_key)
		enc_data = as_rep['enc-part']['cipher']
		print('enc_data %s' % enc_data.hex())
		dec_data = cipher.decrypt(key, 3, enc_data)
		print(dec_data)
		rep =  EncASRepPart.load(dec_data).native
		print(rep)
		cipher = _enctype_table[ int(rep['key']['keytype'])]
		session_key = Key(cipher.enctype, rep['key']['keyvalue'])
		return session_key, cipher, rep

		

	async def sign(self, data, message_no, direction = 'init'):
		raise NotImplementedError()
		
	async def encrypt(self, data, message_no):
		raise NotImplementedError()
		
	async def decrypt(self, data, message_no, direction='init', auth_data=None):
		raise NotImplementedError()
	
	async def authenticate(self, authData, flags = None, seq_number = 0, is_rpc = False):
		if self.iteractions == 0:
			self.setup()
			self.iteractions += 1
			#authdata should be 0 at this point
			#issuer, self._asReq = build_as_req_negoEx(self._userCert, self._certPass, self._remoteComputer, self._diffieHellmanExchange)
			asreqbody = self.__build_asreq()
			asreq = self.__build_pkinit_pa(asreqbody)

			negodata = generate_init_nego(self._msgctr, self._convid)
			self._msgctr += 1
			metadata = self.__get_metadata()
			self._msgctr += 1
			ap_req = generate_ap_req(self._msgctr, self._convid, asreq)
			self._msgctr += 1
			msg = negodata + metadata + ap_req

			return msg, True, None

		if self.iteractions:
			self.iteractions += 1
			
			msgs = negoexts_parse_bytes(authData)
			#print(msgs[MESSAGE_TYPE.CHALLENGE].Exchange.inner_token.native)
			as_rep = msgs[MESSAGE_TYPE.CHALLENGE].Exchange.inner_token.native
			session_key, cipher, rep = self.__decrypt_pk_dh(as_rep)
			







async def amain():
	pfx12_file = 'C:\\Users\\testadmin\\Desktop\\CURRENT_USER_My_0_testadmin@infoskelsecprojects.onmicrosoft.com.pfx'
	pfx12_file_pass = 'mimikatz'
	target = SMBTarget(ip='157.55.176.219')
	settings = SPNEGOEXAuthHandlerSettings(pfx12_file, pfx12_file_pass, target)
	handler = SPNEGOEXAuthHandler(settings)
	msg = await handler.authenticate(None)
	print(msg.hex())



def main():
	import asyncio
	asyncio.run(amain())

if __name__ == '__main__':
	main()