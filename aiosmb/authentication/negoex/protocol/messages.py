import enum
import io
import uuid
import os

# https://tools.ietf.org/html/draft-zhu-negoex-04

# UCHAR is the data type for a one-octet number.
# ULONG is the data type for a 4-octet number encoded in little endian.
# USHORT is the data type for a 2-octet number encoded in little endian.
# ULONG64 is the data type for a 8-octet number encoded in little endian.
# GUID is the data type for a 16-octet number encoded in little endian.

from asn1crypto import core
from asn1crypto.x509 import NameTypeAndValue, NameType
from minikerberos.protocol.asn1_structs import PrincipalName, Checksum

# KerberosV5Spec2 DEFINITIONS EXPLICIT TAGS ::=
TAG = 'explicit'

# class
UNIVERSAL = 0
APPLICATION = 1
CONTEXT = 2


########

# GSS_EXTS_FINISHED             2 #Data type for the IAKERB checksum.
# corresponding checksum type: KEY_USAGE_FINISHED            41
# https://tools.ietf.org/html/draft-ietf-kitten-iakerb-03
class KRB_FINISHED(core.Sequence):
    _fields = [
        ('gss-mic', Checksum, {'tag_type': TAG, 'tag': 1}),
    ]

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/1aeca7fb-d6b4-4402-8fa4-6ec3e955c16e
class KERB_AD_RESTRICTION_ENTRY(core.Sequence):
    _fields = [
        ('restriction-type', core.Integer, {'tag_type': TAG, 'tag': 0}),
        ('restriction', core.OctetString, {'tag_type': TAG, 'tag': 1}),
    ]
    
class KERB_AD_RESTRICTION_ENTRYS(core.SequenceOf):
    _child_spec = KERB_AD_RESTRICTION_ENTRY

########

class NameTypeAndValueBMP(core.Sequence):
    _fields = [
        ('type', core.ObjectIdentifier),
        ('value', core.BMPString),
    ]

class Dunno1(core.SetOf):
	_child_spec = NameTypeAndValueBMP

class Dunno2(core.SequenceOf):
	_child_spec = Dunno1

class Info(core.Sequence):
	_fields = [
		('pku2u', core.GeneralString, {'tag_type': TAG, 'tag': 0}),
		('clientInfo', PrincipalName, {'tag_type': TAG, 'tag': 1}),
	]

class CertIssuer(core.Sequence):
	_fields = [
		('data', core.OctetString, {'tag_type': 'implicit', 'tag': 0}), # there is another ASN1 encoded blob here that contains the issuer. Classes X and Y deal with that. No documentation....
	]

class CertIssuers(core.SequenceOf):
	_child_spec = CertIssuer

class MetaData(core.Sequence):
	_fields = [
		('1', CertIssuers, {'tag_type': TAG, 'tag': 0}), 
		('Info', Info, {'tag_type': TAG, 'tag': 1}),
	]

#### RFC4556 # https://tools.ietf.org/html/rfc4556 ####

from asn1crypto.keys import PublicKeyInfo as SubjectPublicKeyInfo
from asn1crypto.x509 import AlgorithmIdentifier
from minikerberos.protocol.asn1_structs import EncryptionKey, Checksum, KerberosTime, Realm


class DHNonce(core.OctetString):
	pass

class AlgorithmIdentifiers(core.SequenceOf):
	_child_spec = AlgorithmIdentifier

class TD_DH_PARAMETERS(core.SequenceOf):
	_child_spec = AlgorithmIdentifier

class ReplyKeyPack(core.Sequence):
	_fields = [
		('replyKey', EncryptionKey, {'tag_type': TAG, 'tag': 0}), 
		('asChecksum', Checksum, {'tag_type': TAG, 'tag': 1}),
		('dhKeyExpiration', KerberosTime, {'tag_type': TAG, 'tag': 2, 'optional': True}),
	]

class KDCDHKeyInfo(core.Sequence):
	_fields = [
		('subjectPublicKey', core.BitString, {'tag_type': TAG, 'tag': 0}), 
		('nonce', core.Integer, {'tag_type': TAG, 'tag': 1}),
		('dhKeyExpiration', KerberosTime, {'tag_type': TAG, 'tag': 2, 'optional': True}),
	]

class DHRepInfo(core.Sequence):
	_fields = [
		('dhSignedData', core.OctetString, {'tag_type': 'implicit', 'tag': 0}), 
		('serverDHNonce', DHNonce, {'tag_type': TAG, 'tag': 1, 'optional': True}),

	]

class PA_PK_AS_REP(core.Choice):
	_alternatives = [
		('dhInfo', DHRepInfo, {'explicit': (CONTEXT,0) }  ),
		('encKeyPack', core.OctetString, {'implicit': (CONTEXT,1) }  ),
	]

class ExternalPrincipalIdentifier(core.Sequence):
	_fields = [
		('subjectName', core.OctetString, {'tag_type': 'implicit', 'tag': 0, 'optional' : True}), 
		('issuerAndSerialNumber', core.OctetString, {'tag_type': 'implicit', 'tag': 1, 'optional' : True}),
		('subjectKeyIdentifier', core.OctetString, {'tag_type': 'implicit', 'tag': 2, 'optional' : True}), 
	]

class ExternalPrincipalIdentifiers(core.SequenceOf):
	_child_spec = ExternalPrincipalIdentifier

class AD_INITIAL_VERIFIED_CAS(core.SequenceOf):
	_child_spec = ExternalPrincipalIdentifier

class KRB5PrincipalName(core.Sequence):
	_fields = [
		('realm', Realm, {'tag_type': TAG, 'tag': 0}), 
		('principalName', PrincipalName, {'tag_type': TAG, 'tag': 1}),
	]

class TD_INVALID_CERTIFICATES(core.SequenceOf):
	_child_spec = ExternalPrincipalIdentifier

class TD_TRUSTED_CERTIFIERS(core.SequenceOf):
	_child_spec = ExternalPrincipalIdentifier

class PKAuthenticator(core.Sequence):
	_fields = [
		('cusec', core.Integer, {'tag_type': TAG, 'tag': 0}), 
		('ctime', KerberosTime, {'tag_type': TAG, 'tag': 1}),
		('nonce', core.Integer, {'tag_type': TAG, 'tag': 2}),
		('paChecksum', core.OctetString, {'tag_type': TAG, 'tag': 3, 'optional': True}),
	]

class AuthPack(core.Sequence):
	_fields = [
		('pkAuthenticator', PKAuthenticator, {'tag_type': TAG, 'tag': 0}), 
		('clientPublicValue', SubjectPublicKeyInfo, {'tag_type': TAG, 'tag': 1, 'optional' : True}),
		('supportedCMSTypes', AlgorithmIdentifiers, {'tag_type': TAG, 'tag': 2, 'optional' : True}), 
		('clientDHNonce', DHNonce, {'tag_type': TAG, 'tag': 3, 'optional' : True}), 

	]

class PA_PK_AS_REQ(core.Sequence):
	_fields = [
		('signedAuthPack', core.OctetString, {'tag_type': 'implicit', 'tag': 0}), 
		('trustedCertifiers', ExternalPrincipalIdentifiers, {'tag_type': TAG, 'tag': 1, 'optional' : True}),
		('kdcPkId', core.OctetString, {'tag_type': 'implicit', 'tag': 2, 'optional' : True}), 
	]

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/ec551137-c5e5-476a-9c89-e0029473c41b

class LSAP_TOKEN_INFO_INTEGRITY:
	def __init__(self):
		self.Flags = None # unsigned long
		self.TokenIL = None # unsigned long
		self.MachineID = os.urandom(32) # KILE implements a 32-byte binary random string machine ID.

	def to_bytes(self):
		t = self.Flags.to_bytes(4, byteorder='little', signed = False)
		t += self.TokenIL.to_bytes(4, byteorder='little', signed = False)
		t += self.MachineID
		return t
	
	@staticmethod
	def from_bytes(data):
		return LSAP_TOKEN_INFO_INTEGRITY.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		msg = LSAP_TOKEN_INFO_INTEGRITY()
		msg.Flags = int.from_bytes(buff.read(4), byteorder='little', signed = False)
		msg.TokenIL = int.from_bytes(buff.read(4), byteorder='little', signed = False)
		msg.MachineID = buff.read(32)
		return msg





from minikerberos.protocol.asn1_structs import AS_REQ, AS_REP, AP_REQ, AP_REP

NEGOEXTS_DEFAULT_AUTHID = uuid.UUID(bytes_le=bytes.fromhex('5c33530deaf90d4db2ec4ae3786ec308'))

def cl_bytes(data):
	return cl_buff(io.BytesIO(data))

def cl_buff(buff):
	x = buff.read(1)
	if x[0] <= 127:
		return x[0]
	else:
		bcount = x[0] - 128
		y = buff.read(bcount)
		return int.from_bytes(y, byteorder = 'big', signed = False)

class PKU2U_TOKEN_TYPE(enum.Enum):
	KRB_AP_REQ = b'\x01\x00'
	KRB_AP_REP = b'\x02\x00'
	KRB_ERROR  = b'\x03\x00'
	KRB_AS_REQ = b'\x05\x00'
	KRB_AS_REP = b'\x06\x00'

class PKU2U_TOKEN:
	def __init__(self, tok_id = b'\x01\x00'):
		self.tok_id = tok_id
		self.inner_token = None
		#self.inner_token_raw = None #unparsed bytes
		self._pku2u_oid = bytes.fromhex('2b0601050207')
	
	@staticmethod
	def from_bytes(data):
		return PKU2U_TOKEN.from_buffer(io.BytesIO(data))
		
	@staticmethod
	def from_buffer(buff):
		t = PKU2U_TOKEN()
		t_hdr = buff.tell()
		buff.read(1) # 0x60
		total_length = cl_buff(buff)
		buff.read(1) # 0x06
		total_length += buff.tell() - t_hdr - 1
		oid_length = cl_buff(buff)
		t_oid = buff.read(oid_length)
		t.tok_id = PKU2U_TOKEN_TYPE(buff.read(2))
		t_data = buff.read(total_length - buff.tell())
		#t.inner_token_raw = t_data

		if t.tok_id == PKU2U_TOKEN_TYPE.KRB_AS_REQ:
			t.inner_token = AS_REQ.load(t_data)
		elif t.tok_id == PKU2U_TOKEN_TYPE.KRB_AS_REP:
			t.inner_token = AS_REP.load(t_data)
		elif t.tok_id == PKU2U_TOKEN_TYPE.KRB_AP_REQ:
			t.inner_token = AP_REQ.load(t_data)
		elif t.tok_id == PKU2U_TOKEN_TYPE.KRB_AP_REP:
			t.inner_token = AP_REP.load(t_data)
		else:
			t.inner_token = t_data
		return t
		
	def length_encode(self, x):
		if x <= 127:
			return x.to_bytes(1, 'big', signed = False)
		else:
			lb = x.to_bytes((x.bit_length() + 7) // 8, 'big')
			t = (0x80 | len(lb)).to_bytes(1, 'big', signed = False)
			return t+lb
		
	def to_bytes(self):
		data = b'\x06'
		data += self.length_encode(len(self._pku2u_oid))
		data += self._pku2u_oid
		data += self.tok_id.value
		data += self.inner_token

		t = b'\x60'
		t += self.length_encode(len(data)) #+2 ?
		t += data
		return t


class MESSAGE_TYPE(enum.Enum):
	INITIATOR_NEGO = 0
	ACCEPTOR_NEGO = 1
	INITIATOR_META_DATA = 2
	ACCEPTOR_META_DATA = 3
	CHALLENGE = 4
	AP_REQUEST = 5
	VERIFY = 6
	ALERT = 7

NEGOEXT_MESSAGE_TYPES = [MESSAGE_TYPE.INITIATOR_NEGO, MESSAGE_TYPE.CHALLENGE, MESSAGE_TYPE.INITIATOR_META_DATA, MESSAGE_TYPE.ACCEPTOR_META_DATA, MESSAGE_TYPE.AP_REQUEST,  MESSAGE_TYPE.VERIFY,  MESSAGE_TYPE.ALERT]


class BYTE_VECTOR:
	"""
		BYTE_VECTOR encapsulates a variable length array of octets (or bytes)
		that are stored consecutively.  Each element in is a byte (8 bits).
	"""
	def __init__(self):
		self.ByteArrayOffset = None #ULONG 
		self.ByteArrayLength = None #ULONG

class AUTH_SCHEME_VECTOR:
	"""
		AUTH_SCHEME_VECTOR encapsulates a variable length array of
		AUTH_SCHEMEs that are stored consecutively.  Each element is a
		structure of the type AUTH_SCHEME.
	"""
	def __init__(self):
		self.AuthSchemeArrayOffset = None #ULONG // each element contains an AUTH_SCHEME
		self.AuthSchemeCount = None #ULONG

class EXTENSION_VECTOR:
	"""
		EXTENSION_VECTOR encapsulates a variable length array of EXTENSIONs
		that are stored consecutively.  Each element is a structure of the
		type EXTENSION.

	"""
	def __init__(self):
		self.ExtensionArrayOffset = None #ULONG // each element contains an AUTH_SCHEME
		self.ExtensionCount = None #ULONG

class EXTENSION:
	"""
	This part is not tested, as the RFC doesn't define any extensions at the moment!
	"""
	def __init__(self):
		self.ExtensionType = None #ULONG 
		self.ExtensionArrayOffset = None #ULONG 
		self.ExtensionArrayLength = None #ULONG

		self.ExtensionValue = None #BYTE_VECTOR

	@staticmethod
	def from_bytes(data):
		return EXTENSION.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		msg = EXTENSION()
		msg.ExtensionType = int.from_bytes(buff.read(4), byteorder='little', signed = False)
		msg.ExtensionArrayOffset = int.from_bytes(buff.read(4), byteorder='little', signed = False)
		msg.ExtensionArrayLength = int.from_bytes(buff.read(4), byteorder='little', signed = False)

		buff.seek(msg.ExtensionArrayOffset)
		msg.ExtensionValue = buff.read(msg.ExtensionArrayLength)
		return msg

class CHECKSUM:
	#define CHECKSUM_SCHEME_RFC3961 1 - Currently only one value is defined.
	def __init__(self):
		self.cbHeaderLength = 20 #ULONG, always 20
		self.ChecksumScheme = None #ULONG 
		self.ChecksumType = None #ULONG // in the case of RFC3961 scheme, this is the RFC3961 checksum type
		self.ChecksumArrayOffset = None
		self.ChecksumArrayLength = None
		
		self.ChecksumValue = None #BYTE_VECTOR

	@staticmethod
	def from_bytes(data):
		return CHECKSUM.from_buffer(io.BytesIO(data))
		
	@staticmethod
	def from_buffer(buff):
		start_offset = buff.tell()
		msg = CHECKSUM()
		msg.cbHeaderLength = int.from_bytes(buff.read(4), byteorder='little', signed = False)
		msg.ChecksumScheme = int.from_bytes(buff.read(4), byteorder='little', signed = False)
		msg.ChecksumType = int.from_bytes(buff.read(4), byteorder='little', signed = False)
		msg.ChecksumArrayOffset = int.from_bytes(buff.read(4), byteorder='little', signed = False)
		msg.ChecksumArrayLength = int.from_bytes(buff.read(4), byteorder='little', signed = False)

		if msg.ChecksumArrayLength != 0:
			buff.seek(msg.ChecksumArrayOffset)
			msg.ChecksumValue = buff.read(msg.ChecksumArrayLength)

		return msg

class MESSAGE_HEADER:
	#define MESSAGE_SIGNATURE    0x535458454f47454ei64
	def __init__(self):
		self.Signature = b'NEGOEXTS'
		self.MessageType = None #MESSAGE_TYPE enum
		self.SequenceNum = None #ULONG  the message sequence number of this, conversation, starting with 0 and sequentially incremented
		self.cbHeaderLength = None #ULONG // the header length of this message, including the message specific header, excluding the payload
		self.cbMessageLength = None #ULONG // the length of this message
		self.ConversationId = None #CONVERSATION_ID
		self._hdrsize = 40

	def to_bytes(self):
		t = self.Signature
		t += self.MessageType.value.to_bytes(4, byteorder='little', signed = False)
		t += self.SequenceNum.to_bytes(4, byteorder='little', signed = False)
		t += self.cbHeaderLength.to_bytes(4, byteorder='little', signed = False)
		t += self.cbMessageLength.to_bytes(4, byteorder='little', signed = False)
		t += self.ConversationId
		return t
	
	@staticmethod
	def from_bytes(data):
		return MESSAGE_HEADER.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		msg = MESSAGE_HEADER()
		msg.Signature = buff.read(8)
		msg.MessageType = MESSAGE_TYPE(int.from_bytes(buff.read(4), byteorder='little', signed = False))
		msg.SequenceNum = int.from_bytes(buff.read(4), byteorder='little', signed = False)
		msg.cbHeaderLength = int.from_bytes(buff.read(4), byteorder='little', signed = False)
		msg.cbMessageLength = int.from_bytes(buff.read(4), byteorder='little', signed = False)
		msg.ConversationId = buff.read(16) # guid, but basically doesnt matter
		return msg

class NEGO_MESSAGE:
	def __init__(self):
		self.Header = None #MESSAGE_HEADER
		self.Random = os.urandom(32) # 32 bytes
		self.ProtocolVersion = 0 #ULONG64  // version of the protocol, this contains 0
		self.AuthSchemeArrayOffset = 0 #ULONG // each element contains an AUTH_SCHEME
		self.AuthSchemeCount = 0 #ULONG
		self.ExtensionArrayOffset = 0 #ULONG // each element contains an AUTH_SCHEME
		self.ExtensionCount = 0 #ULONG
		self.msgsize = 40+32+8+4+4+4+4
		
		self.Extensions = []
		self.AuthSchemes = [NEGOEXTS_DEFAULT_AUTHID]
	
	def to_bytes(self):
		self.Header.cbHeaderLength = self.msgsize
		self.AuthSchemeArrayOffset = self.msgsize
		buff = io.BytesIO()
		for auth in self.AuthSchemes:
			buff.write(auth.bytes_le)
			self.AuthSchemeCount += 1
		buff.seek(0)
		payload = buff.read()
		buff = io.BytesIO()
		if len( self.Extensions) > 0:
			self.ExtensionArrayOffset = self.msgsize + len(payload)
			for ext in self.Extensions:
				ext.to_buffer(buff)
				self.ExtensionCount += 1
			
		buff.seek(0)
		payload += buff.read()

		self.Header.cbMessageLength = self.msgsize + len(payload)
		

		res = self.Header.to_bytes()
		res += self.Random
		res += self.ProtocolVersion.to_bytes(8, byteorder='little', signed = False)
		res += self.AuthSchemeArrayOffset.to_bytes(4, byteorder='little', signed = False)
		res += self.AuthSchemeCount.to_bytes(4, byteorder='little', signed = False)
		res += self.ExtensionArrayOffset.to_bytes(4, byteorder='little', signed = False)
		res += self.ExtensionCount.to_bytes(4, byteorder='little', signed = False)
		res += payload

		return res
	
	@staticmethod
	def from_bytes(data):
		return NEGO_MESSAGE.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		start_offset = buff.tell()
		msg = NEGO_MESSAGE()
		msg.Header = MESSAGE_HEADER.from_buffer(buff)
		msg.Random = buff.read(32)
		msg.ProtocolVersion = int.from_bytes(buff.read(8), byteorder='little', signed = False)
		msg.AuthSchemeArrayOffset = int.from_bytes(buff.read(4), byteorder='little', signed = False)
		msg.AuthSchemeCount = int.from_bytes(buff.read(4), byteorder='little', signed = False)
		msg.ExtensionArrayOffset = int.from_bytes(buff.read(4), byteorder='little', signed = False)
		msg.ExtensionCount = int.from_bytes(buff.read(4), byteorder='little', signed = False)
		
		msg.AuthSchemes = []
		if msg.AuthSchemeCount != 0:
			buff.seek(start_offset + msg.AuthSchemeArrayOffset)
			for i in range(msg.AuthSchemeCount):
				auth_data = buff.read(16) # AUTH_SCHEME is a GUID
				msg.AuthSchemes.append(uuid.UUID(bytes_le=auth_data))

		if msg.ExtensionCount != 0:
			buff.seek(start_offset + msg.ExtensionArrayOffset)
			ext_data = EXTENSION.from_buffer(buff)
			msg.Extensions.append(ext_data)


		#msg.AuthSchemes = AUTH_SCHEME_VECTOR.from_buffer(buff)
		#msg.Extensions = EXTENSION_VECTOR.from_buffer(buff)
		return msg


class EXCHANGE_MESSAGE:
	def __init__(self):
		self.Header = None #MESSAGE_HEADER // MESSAGE_TYPE_CHALLENGE for the acceptor, or MESSAGE_TYPE_AP_REQUEST for the initiator MESSAGE_TYPE_INITiATOR_META_DATA for the initiator metadata MESSAGE_TYPE_ACCEPTOR_META_DATA for the acceptor metadata
		self.AuthScheme = None #AUTH_SCHEME
		self.ExchangeOffset = None
		self.ExchangeByteCount = None
		self.Exchange = None #BYTE_VECTOR  // contains the opaque handshake message for the authentication scheme
		self.msgsize = 40 + 16 + 4 + 4
		self.exchange_data_raw = None

	def to_bytes(self):
		self.ExchangeByteCount = len(self.Exchange)
		self.ExchangeOffset = self.msgsize
		self.Header.cbMessageLength = self.msgsize + self.ExchangeByteCount
		self.Header.cbHeaderLength = self.msgsize

		res = self.Header.to_bytes()
		res += self.AuthScheme.bytes_le
		res += self.ExchangeOffset.to_bytes(4, byteorder='little', signed = False)
		res += self.ExchangeByteCount.to_bytes(4, byteorder='little', signed = False)
		res += self.Exchange

		return res


	@staticmethod
	def from_bytes(data):
		return EXCHANGE_MESSAGE.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		start_offset = buff.tell()
		msg = EXCHANGE_MESSAGE()
		msg.Header = MESSAGE_HEADER.from_buffer(buff)
		msg.AuthScheme = uuid.UUID(bytes_le=buff.read(16))
		msg.ExchangeOffset = int.from_bytes(buff.read(4), byteorder='little', signed = False)
		msg.ExchangeByteCount = int.from_bytes(buff.read(4), byteorder='little', signed = False)
		buff.seek(start_offset + msg.ExchangeOffset)
		exch_data = buff.read(msg.ExchangeByteCount)
		msg.exchange_data_raw = exch_data
		
		if msg.Header.MessageType in [MESSAGE_TYPE.AP_REQUEST, MESSAGE_TYPE.CHALLENGE]:
			token = PKU2U_TOKEN.from_bytes(exch_data)
			msg.Exchange = token
		
		elif msg.Header.MessageType in [MESSAGE_TYPE.INITIATOR_META_DATA, MESSAGE_TYPE.ACCEPTOR_META_DATA]:
			token = MetaData.load(exch_data)
			#x = X.load(token.native['1'][0]['data'])
			msg.Exchange = token
		
		else:
			msg.Exchange = exch_data
		return msg


class VERIFY_MESSAGE:
	def __init__(self):
		self.Header = None # MESSAGE_HEADER  // MESSAGE_TYPE_VERIFY
		self.AuthScheme = None #AUTH_SCHEME

		self.cbHeaderLength = 20 #ULONG, always 20
		self.ChecksumScheme = 1 #ULONG RFC3961
		self.ChecksumType = None #ULONG // in the case of RFC3961 scheme, this is the RFC3961 checksum type
		self.ChecksumArrayOffset = None
		self.ChecksumArrayLength = None
		self.Checksum = None
		self.msgsize = 40 + 16 + 20 + 4
	
	def to_bytes(self):
		self.ChecksumArrayLength = len(self.Checksum)
		self.ChecksumArrayOffset = self.msgsize
		self.Header.cbMessageLength = self.msgsize + len(self.Checksum)
		self.Header.cbHeaderLength = self.msgsize

		res = self.Header.to_bytes()
		res += self.AuthScheme.bytes_le
		res += self.cbHeaderLength.to_bytes(4, byteorder='little', signed = False)
		res += self.ChecksumScheme.to_bytes(4, byteorder='little', signed = False)
		res += self.ChecksumType.to_bytes(4, byteorder='little', signed = False)
		res += self.ChecksumArrayOffset.to_bytes(4, byteorder='little', signed = False)
		res += self.ChecksumArrayLength.to_bytes(4, byteorder='little', signed = False)
		res += b'\x00' * 4 # manually adding pad
		res += self.Checksum

		return res
	
	@staticmethod
	def from_bytes(data):
		return VERIFY_MESSAGE.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		start_offset = buff.tell()
		msg = VERIFY_MESSAGE()
		msg.Header = MESSAGE_HEADER.from_buffer(buff)
		msg.AuthScheme = uuid.UUID(bytes_le=buff.read(16))

		msg.cbHeaderLength = int.from_bytes(buff.read(4), byteorder='little', signed = False)
		msg.ChecksumScheme = int.from_bytes(buff.read(4), byteorder='little', signed = False)
		msg.ChecksumType = int.from_bytes(buff.read(4), byteorder='little', signed = False)
		msg.ChecksumArrayOffset = int.from_bytes(buff.read(4), byteorder='little', signed = False)
		msg.ChecksumArrayLength = int.from_bytes(buff.read(4), byteorder='little', signed = False)

		if msg.ChecksumArrayLength != 0:
			buff.seek(msg.ChecksumArrayOffset)
			msg.Checksum = buff.read(msg.ChecksumArrayLength)
		return msg


class ALERT_MESSAGE:
	def __init__(self):
		self.Header = None #MESSAGE_HEADER
		self.AuthScheme = None #AUTH_SCHEME
		self.ErrorCode = None# ULONG // an NTSTATUS code
		self.AlertArrayOffset = None
		self.AlertCount = None

		self.Alerts = []

	@staticmethod
	def from_bytes(data):
		return ALERT_MESSAGE.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		start_offset = buff.tell()
		msg = ALERT_MESSAGE()
		msg.Header = MESSAGE_HEADER.from_buffer(buff)
		msg.AuthScheme = uuid.UUID(bytes_le=buff.read(16))
		msg.ErrorCode = int.from_bytes(buff.read(4), byteorder='little', signed = False)
		msg.AlertArrayOffset = int.from_bytes(buff.read(4), byteorder='little', signed = False)
		msg.AlertCount = int.from_bytes(buff.read(4), byteorder='little', signed = False)

		if msg.AlertCount != 0:
			buff.seek(start_offset + msg.AlertArrayOffset)
			for _ in range(msg.AlertCount):
				msg.Alerts.append(Alert.from_buffer(buff))


		return msg

class ALERT_TYPE(enum.Enum):
	PULSE = 1

class ALERT_VERIFY(enum.Enum):
	NO_KEY = 1

class ALERT_PULSE:
	def __init__(self):
		self.cbHeaderLength = None
		self.Reason = None

class ALERT:
	def __init__(self):
		self.AlertType = None # MESSAGE_HEADER  // MESSAGE_TYPE_VERIFY
		self.AlertDataOffset = None
		self.AlertDataLength = None

		self.AlertValue = None # BYTE_VECTOR //alert types
	
	@staticmethod
	def from_bytes(data):
		return ALERT.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		start_offset = buff.tell()
		msg = ALERT()
		msg.AlertType = ALERT_TYPE(int.from_bytes(buff.read(4), byteorder='little', signed = False))
		msg.AlertDataOffset = int.from_bytes(buff.read(4), byteorder='little', signed = False)
		msg.AlertDataLength = int.from_bytes(buff.read(4), byteorder='little', signed = False)

		if msg.AlertDataLength != 0:
			buff.seek(msg.AlertDataOffset)
			msg.AlertValue = buff.read(msg.AlertDataLength)
		
		return msg


def generate_initiator_metadata(seq_number, conv_id, metadata, authscheme = NEGOEXTS_DEFAULT_AUTHID):
	hdr = MESSAGE_HEADER()
	hdr.MessageType = MESSAGE_TYPE.INITIATOR_META_DATA #MESSAGE_TYPE enum
	hdr.SequenceNum = seq_number
	hdr.ConversationId = conv_id

	em = EXCHANGE_MESSAGE()
	em.Header = hdr
	em.AuthScheme = authscheme
	em.Exchange = metadata

	return em.to_bytes()

def generate_init_nego(seq_number, conv_id, authschemes = None, extensions = None):
	hdr = MESSAGE_HEADER()
	hdr.MessageType = MESSAGE_TYPE.INITIATOR_NEGO
	hdr.SequenceNum = seq_number
	hdr.ConversationId = conv_id

	nego = NEGO_MESSAGE()
	nego.Header = hdr
	if authschemes is not None:
		nego.AuthSchemes = authschemes
	if extensions is not None:
		nego.Extensions = extensions

	return nego.to_bytes()

def generate_ap_req(seq_number, conv_id, ap_req, tok_type, authscheme = NEGOEXTS_DEFAULT_AUTHID):
	hdr = MESSAGE_HEADER()
	hdr.MessageType = MESSAGE_TYPE.AP_REQUEST
	hdr.SequenceNum = seq_number
	hdr.ConversationId = conv_id

	exchange = EXCHANGE_MESSAGE()
	exchange.Header = hdr
	exchange.AuthScheme = authscheme
	token = PKU2U_TOKEN()
	token.tok_id = tok_type #PKU2U_TOKEN_TYPE.KRB_AS_REQ
	token.inner_token = ap_req
	exchange.Exchange = token.to_bytes()
	return exchange.to_bytes(), token.to_bytes()

def generate_verify(seq_number, conv_id, checksum, checksumtype, authscheme = NEGOEXTS_DEFAULT_AUTHID):
	hdr = MESSAGE_HEADER()
	hdr.MessageType = MESSAGE_TYPE.VERIFY
	hdr.SequenceNum = seq_number
	hdr.ConversationId = conv_id

	verify = VERIFY_MESSAGE()
	verify.Header = hdr
	verify.AuthScheme = authscheme
	verify.Checksum = checksum
	verify.ChecksumType = checksumtype


	return verify.to_bytes()

def negoexts_parse_bytes(data):
	return negoexts_parse_buffer(io.BytesIO(data))

def negoexts_parse_buffer(buff):
	resd = {}
	start = buff.tell()
	buff.seek(0,2)
	end = buff.tell()
	buff.seek(start)
	maxiter = 255
	while buff.tell() != end and maxiter != 0:		
		maxiter -= 1
		start = buff.tell()
		hdr = MESSAGE_HEADER.from_buffer(buff)
		buff.seek(start)
		data = buff.read(hdr.cbMessageLength)
		if hdr.MessageType in [MESSAGE_TYPE.INITIATOR_NEGO, MESSAGE_TYPE.ACCEPTOR_NEGO]:
			res = NEGO_MESSAGE.from_bytes(data)
		elif hdr.MessageType in [MESSAGE_TYPE.CHALLENGE, MESSAGE_TYPE.INITIATOR_META_DATA, MESSAGE_TYPE.ACCEPTOR_META_DATA, MESSAGE_TYPE.AP_REQUEST]:
			res = EXCHANGE_MESSAGE.from_bytes(data)
		elif hdr.MessageType == MESSAGE_TYPE.VERIFY:
			res = VERIFY_MESSAGE.from_bytes(data)
		elif hdr.MessageType == MESSAGE_TYPE.ALERT:
			res = ALERT_MESSAGE.from_bytes(data)
		
		resd[hdr.MessageType] = res

	if maxiter == 0:
		print('SAD')

	return resd