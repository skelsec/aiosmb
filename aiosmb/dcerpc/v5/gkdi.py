

from aiosmb.dcerpc.v5.ndr import NDRCALL, NDRPOINTER, NDRUniConformantArray
from aiosmb.dcerpc.v5.dtypes import DWORD, NTSTATUS, GUID, RPC_SID, NULL, PGUID, ULONG, LONG, PWCHAR, PULONG
from aiosmb.dcerpc.v5.rpcrt import DCERPCException
from aiosmb.dcerpc.v5 import system_errors
from aiosmb.dcerpc.v5 import hresult_errors
from aiosmb.dcerpc.v5.uuid import uuidtup_to_bin, string_to_bin
from aiosmb.dcerpc.v5.structure import Structure


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
