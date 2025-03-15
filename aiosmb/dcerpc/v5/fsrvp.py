

import io
from os import stat

from aiosmb.dcerpc.v5.dtypes import ULONGLONG, UINT, USHORT, LPWSTR, DWORD, ULONG, NULL, WSTR, PBOOL, PLONG
from aiosmb.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT, NDRUNION, NDRPOINTER, NDRUniConformantArray
from aiosmb.dcerpc.v5.ndr import NDRVaryingString

from aiosmb.dcerpc.v5.rpcrt import DCERPCException
from aiosmb.dcerpc.v5 import system_errors
from aiosmb.dcerpc.v5.uuid import uuidtup_to_bin
from aiosmb.dcerpc.v5.structure import Structure

# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsrvp/
# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsrvp/23382633-78f1-419e-bad0-699dff0c6ef1

MSRPC_UUID_FSRVP = uuidtup_to_bin(('a8e0653c-2744-4389-a61d-7373df8b2292', '1.0'))
#r"\PIPE\FssagentRpc",

class DCERPCSessionError(DCERPCException):
	def __init__(self, error_string=None, error_code=None, packet=None):
		DCERPCException.__init__(self, error_string, error_code, packet)

	def __str__( self ):
		key = self.error_code
		if key in system_errors.ERROR_MESSAGES:
			error_msg_short = system_errors.ERROR_MESSAGES[key][0]
			error_msg_verbose = system_errors.ERROR_MESSAGES[key][1] 
			return 'FSRVP SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
		else:
			return 'FSRVP SessionError: unknown error code: 0x%x' % self.error_code





################################################################################
# STRUCTURES
################################################################################


################################################################################
# Structure defs
################################################################################




################################################################################
# RPC CALLS
################################################################################
class RpcGetSupportedVersion(NDRCALL):
	opnum = 0
	structure = ()

class RpcGetSupportedVersionResponse(NDRCALL):
	structure = (
	   ('MinVersion', DWORD),
	   ('MaxVersion', DWORD),
	)

class RpcIsPathSupported(NDRCALL):
	opnum = 8
	structure = (
	   ('ShareName', LPWSTR),
	)

class RpcIsPathSupportedResponse(NDRCALL):
	structure = (
	   ('SupportedByThisProvider', PBOOL),
	   ('OwnerMachineName', LPWSTR),
	)

class RpcIsPathShadowCopied(NDRCALL):
	opnum = 9
	structure = (
	   ('ShareName', LPWSTR),
	)

class RpcIsPathShadowCopiedResponse(NDRCALL):
	structure = (
	   ('SupportedByThisProvider', PBOOL),
	   ('ShadowCopyCompatibility', PLONG),
	)

################################################################################
# OPNUMs and their corresponding structures
################################################################################
OPNUMS = {
	0  : (RpcGetSupportedVersion, RpcGetSupportedVersionResponse),
	8  : (RpcIsPathSupported, RpcIsPathSupportedResponse),
	9  : (RpcIsPathShadowCopied, RpcIsPathShadowCopiedResponse),
}

################################################################################
# HELPER FUNCTIONS
################################################################################
def checkNullString(string):
	if string == NULL:
		return string

	if string[-1:] != '\x00':
		return string + '\x00'
	else:
		return string

async def hRpcIsPathSupported(dce, pathName):
	request = RpcIsPathSupported()
	request['ShareName'] = checkNullString(pathName)
	return await dce.request(request)

async def hRpcIsPathShadowCopied(dce, pathName):
	request = RpcIsPathSupported()
	request['ShareName'] = checkNullString(pathName)
	return await dce.request(request)