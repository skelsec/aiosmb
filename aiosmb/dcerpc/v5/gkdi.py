
from __future__ import division
from __future__ import print_function
from aiosmb.dcerpc.v5.ndr import NDRCALL, NDRPOINTER, NDRUniConformantArray
from aiosmb.dcerpc.v5.dtypes import DWORD, NTSTATUS, GUID, RPC_SID, NULL, PGUID, ULONG, LONG, PWCHAR, PULONG
from aiosmb.dcerpc.v5.rpcrt import DCERPCException
from aiosmb.dcerpc.v5 import system_errors
from aiosmb.dcerpc.v5 import hresult_errors
from aiosmb.dcerpc.v5.uuid import uuidtup_to_bin, string_to_bin
from aiosmb.dcerpc.v5.structure import Structure
import uuid
import io

# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/943dd4f6-6b80-4a66-8594-80df6d2aad0a
MSRPC_UUID_GKDI = uuidtup_to_bin(('b9785960-524f-11df-8b6d-83dcded72085', '1.0'))

class DCERPCSessionError(DCERPCException):
	def __init__(self, error_string=None, error_code=None, packet=None):
		DCERPCException.__init__(self, error_string, error_code, packet)

	def __str__( self ):
		key = self.error_code
		if key in hresult_errors.ERROR_MESSAGES:
			error_msg_short = hresult_errors.ERROR_MESSAGES[key][0]
			error_msg_verbose = hresult_errors.ERROR_MESSAGES[key][1]
			return 'GKDI SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
		elif key & 0xffff in system_errors.ERROR_MESSAGES:
			error_msg_short = system_errors.ERROR_MESSAGES[key & 0xffff][0]
			error_msg_verbose = system_errors.ERROR_MESSAGES[key & 0xffff][1]
			return 'GKDI SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
		return 'GKDI SessionError: unknown error code: 0x%x' % self.error_code

################################################################################
# STRUCTURES
################################################################################
class BYTE_ARRAY(NDRUniConformantArray):
	item = 'c'

class PBYTE_ARRAY(NDRPOINTER):
	referent = (
		('Data', BYTE_ARRAY),
	)

class FFCDHParameters:
	def __init__(self):
		self.length = None
		self.magic = None
		self.key_length = None
		self.filed_order = None
		self.generator = None
	
	@staticmethod
	def from_bytes(data:bytes):
		return FFCDHParameters.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff:io.BytesIO):
		blob = FFCDHParameters()
		blob.length = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		blob.magic = buff.read(4)
		blob.key_length = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		blob.filed_order = buff.read(blob.key_length)
		blob.generator = buff.read(blob.key_length)
		return blob

	def __str__(self):
		t = ''
		for k in self.__dict__:
			if isinstance(self.__dict__[k], bytes):
				t += '%s: %s\n' % (k, self.__dict__[k].hex())
			else:
				t += '%s: %s\n' % (k, self.__dict__[k])
		return t
	
class KDFParameters:
	def __init__(self):
		self.magic = None
		self.hash_name_length = None
		self.hash_name = None
	
	@staticmethod
	def from_bytes(data:bytes):
		return KDFParameters.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff:io.BytesIO):
		blob = KDFParameters()
		blob.magic = buff.read(8)
		blob.hash_name_length = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		buff.read(4)
		blob.hash_name = buff.read(blob.hash_name_length).decode('utf-16-le').replace('\x00', '')
		return blob

	def __str__(self):
		t = ''
		for k in self.__dict__:
			if isinstance(self.__dict__[k], bytes):
				t += '%s: %s\n' % (k, self.__dict__[k].hex())
			else:
				t += '%s: %s\n' % (k, self.__dict__[k])
		return t


class GroupKeyEnvelope:
	def __init__(self):
		self.version = None
		self.magic = None
		self.is_public_key = None
		self.l0idx = None
		self.l1idx = None
		self.l2idx = None
		self.root_key_identifier = None
		self.kdf_algorithm = None
		self.kdf_parameters = None
		self.secret_algorithm = None
		self.secret_parameters = None
		self.domain_name = None
		self.forest_name = None
		self.l1_key = None
		self.l2_key = None
	
	@staticmethod
	def from_bytes(data:bytes):
		return GroupKeyEnvelope.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff:io.BytesIO):
		blob = GroupKeyEnvelope()
		blob.version = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		blob.magic = buff.read(4)
		blob.is_public_key = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		blob.l0idx = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		blob.l1idx = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		blob.l2idx = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		blob.root_key_identifier = uuid.UUID(bytes_le=buff.read(16))
		kdf_algorithm_length = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		kdf_parameters_length = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		sec_algorithm_length = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		sec_parameters_length = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		priv_key_length = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		pub_key_length = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		l1_key_length = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		l2_key_length = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		domain_name_length = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		forest_name_length = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		blob.kdf_algorithm = buff.read(kdf_algorithm_length).decode('utf-16-le').replace('\x00', '')
		if len(blob.kdf_algorithm) != 0:
			blob.kdf_parameters = KDFParameters.from_bytes(buff.read(kdf_parameters_length))
		blob.secret_algorithm = buff.read(sec_algorithm_length).decode('utf-16-le').replace('\x00', '')
		blob.secret_parameters = FFCDHParameters.from_bytes(buff.read(sec_parameters_length))
		blob.domain_name = buff.read(domain_name_length).decode('utf-16-le').replace('\x00', '')
		blob.forest_name = buff.read(forest_name_length).decode('utf-16-le').replace('\x00', '')
		blob.l1_key = buff.read(l1_key_length)
		blob.l2_key = buff.read(l2_key_length)		
		return blob

	def __str__(self):
		t = ''
		for k in self.__dict__:
			if isinstance(self.__dict__[k], bytes):
				t += '%s: %s\n' % (k, self.__dict__[k].hex())
			else:
				t += '%s: %s\n' % (k, self.__dict__[k])
		return t

################################################################################
# RPC CALLS
################################################################################
# 3.1.4.1 BackuprKey(Opnum 0)
class GetKey(NDRCALL):
	opnum = 0
	structure = (
	   ('cbTargetSD', ULONG),
	   ('pTargetSD', BYTE_ARRAY),
	   ('pRootKeyID', PGUID),
	   ('L0KeyID', LONG),
	   ('L1KeyID', LONG),
	   ('L2KeyID', LONG),
	)

class GetKeyResponse(NDRCALL):
	structure = (
		('pcbOut', ULONG),
		('ppbOut', PBYTE_ARRAY),
	)

################################################################################
# OPNUMs and their corresponding structures
################################################################################
OPNUMS = {
 0 : (GetKey, GetKeyResponse),
}

################################################################################
# HELPER FUNCTIONS
################################################################################
async def hGetKey(dce, targetSD, rootKey, L0KeyID, L1KeyID, L2KeyID):
	request = GetKey()
	request['pTargetSD'] = targetSD
	if targetSD == NULL:
		request['cbTargetSD'] = 0
	else:
		request['cbTargetSD'] = len(targetSD)
	request['pRootKeyID'] = rootKey
	request['L0KeyID'] = L0KeyID
	request['L1KeyID'] = L1KeyID
	request['L2KeyID'] = L2KeyID
	return await dce.request(request)
