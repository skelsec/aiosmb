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
		self.private_key = os.urandom(32)
		self.private_key_int = int(self.private_key.hex(), 16)
	
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
		self.shared_key = pow(bob_int, self.private_key_int, self.p)
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
		kdc_req_body['etype'] = [23, 18,17]
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
		dp['q'] = 0
		
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

		#pkasrep = PA_PK_AS_REP.load(bytes.fromhex('a0820665308206618082063930820635020103310b300906052b0e03021a05003081a406072b060105020302a08198048195308192a0818703818400028180208e0f69f5d60e713a5398837e1bdc7698f06648423d90b9df392ec484b549e81399a968bdc443bf5c56a06da73dd647b0cce26ee4c56297fa4a9d06f51f336f9e14649a01550246cf32a849ae1b4ebff897294bf95fe87fc771b38bf28964322f52d03d8b9dac332b067dc71c4bedcf0e891e80557224c5e5ccbce0439e24e7a10602046292c3a0a08203af308203ab30820293a0030201020210414135227b1a4ba5647832c1277770b0300d06092a864886f70d01010b0500304d314b304906035504031e42004d0053002d004f007200670061006e0069007a006100740069006f006e002d005000320050002d0041006300630065007300730020005b0032003000320031005d301e170d3231303530313230333134375a170d3231303530323230333634375a306531343032060a0992268993f22c640119162430663965653539642d366137632d343333392d383264322d336534633935366564343666312d302b06035504030c2431666633616363662d383262302d343230322d393831632d66333033343562653766323730820122300d06092a864886f70d01010105000382010f003082010a0282010100bbaf9cc572c606d9e22ff78bcb1583ab62a0830036cb62259bf5f177b8de4ed63e9b5ea5164355b9db128e31a443fe11f13a197524411d7a51ee6e98e14ad66df32e5dd1701a04ab200455dcac195c92c064927cb80cbcb864da5e78266f24129d02dc5ee4eb459c84e1c100b08c26ec07ac6409a2dbda7091043fc529c089607c058254e178021d8e22da6a526351cd0567e025f3e1fafef4de023c7d959608b7b3eea8af63c743acae742ecc76cb3532ab6db74056b2de8d69142b0aad2b93dedddfd15fe9d986e0e4af65e7f3904b5455277f2365f25365a8606cff19f3263094cbdc342ef048141d4de4b7caa679757affceb20b21540c16c1008bd9b1bd0203010001a36f306d300e0603551d0f0101ff0404030205a030290603551d11042230208209617a616474657374318209617a61647465737431820831302e302e302e3430130603551d25040c300a06082b06010505070301301b06092b060104018237150a040e300c300a06082b06010505070301300d06092a864886f70d01010b050003820101000bd995a9a2e51eb8cdbdef7386c5611332051597115cf4e7e5b9f4dddf8f2d579066522635cc32be053c842cb7c56f24d9c5ffe79c638232c13619bb50a5329877389a7a6035631f61fca602d3b019ddc69ed825dd6190a9f6977de571c7a3e86dd669dacd4b78cf1b87f2adc4fcf7bc170cfa613831f57dd66d929a99c187b0ba6d5b40b516e8372827ebb4abf91eedf58645ce3d09612941bb90711b3627ca5fe57daa46ffcd0d16738173fdecd18115d9d9d491c4415566f7fdf9dba5dbbbdeea84d8814237e45c48788ae2c846694ce981ff6353208889de91a5460e0d3b1635c3b8efee3433aa426790de8a220dacddc8e301c3b23cea53ef247df9bd54318201c7308201c30201013061304d314b304906035504031e42004d0053002d004f007200670061006e0069007a006100740069006f006e002d005000320050002d0041006300630065007300730020005b0032003000320031005d0210414135227b1a4ba5647832c1277770b0300906052b0e03021a0500a03d301606092a864886f70d010903310906072b060105020302302306092a864886f70d0109043116041421ec92a30e967cdd5182b2ff6eafd65e127938f3300d06092a864886f70d0101010500048201009b6f5eb1aa21e0a101bafef173603a181080da6f104919772edd0cd09bb91e933ecc62b2d18ac63e60dd17a714b860b0452c4ebc2963da25f0a010ce05c78331c7d79d4af4fdc96efdb1b078f78c07897eff50c8d9da91fc5fd5999d42e2f49215f2a507350d46967eb466b104a6374ef87a99eda87b50f956e815fd4c118e69f8057c7e25471af4359ab972e2c8c7724c55a255b63670aba4883923c6b8feab10ff0f8987fd04615be122056ded99b1e7884e805ecd3b6ee0638b0448b8ed125fa47c4bbc423d1fa878adb711e77f86035d9c7c320e6bcfa516ae858f9dafbfe9506dc939558bf55a1bb272a70d03feea838859e0e9d5177353217edb8058eda122042040ee7ac8a8b09d9d7178d2c20f58862963c75261d4b9890152b421ef88b22d24')).native
		#input(pa['padata-value'].hex())
		sd = cms.SignedData.load(pkasrep['dhSignedData']).native
		keyinfo = sd['encap_content_info']
		if keyinfo['content_type'] != '1.3.6.1.5.2.3.2':
			raise Exception('Keyinfo content type unexpected value')
		authdata = KDCDHKeyInfo.load(keyinfo['content']).native
		input(authdata['subjectPublicKey'])
		pubkey = int(''.join(['1'] + [str(x) for x in authdata['subjectPublicKey']]), 2)
		print(''.join([str(x) for x in authdata['subjectPublicKey']]))
		
		print(core.BitString(authdata['subjectPublicKey']).dump().hex())
		
		print('pubkey_hex %s' % core.BitString(authdata['subjectPublicKey']).dump()[7:].hex())
		pubkey = int.from_bytes(core.BitString(authdata['subjectPublicKey']).dump()[7:], 'big', signed = False)
		print('pubkey %s' % pubkey)
		shared_key = self.diffie.exchange(pubkey)
		shared_key = shared_key.to_bytes((shared_key.bit_length() + 7) // 8, 'big')
		print('shared_key %s' % shared_key.hex())
		
		
		
		
		server_nonce = pkasrep['serverDHNonce']
		input('server_nonce \r\n%s' % pkasrep['serverDHNonce'].hex())
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
		dec_data = cipher.decrypt(key, 3, enc_data)
		print(dec_data)
		rep = dec_data
		cipher = _enctype_table[ int(encASRepPart['key']['keytype'])]
		session_key = Key(cipher.enctype, encASRepPart['key']['keyvalue'])
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