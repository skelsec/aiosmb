

import io
from os import stat

from aiosmb.dcerpc.v5.dtypes import LONG, BOOL, PWCHAR, RPC_SID, PCHAR, ULONGLONG, UINT, USHORT, LPWSTR, DWORD, ULONG, NULL, WSTR, PBOOL, PLONG
from aiosmb.dcerpc.v5.ndr import NDRPOINTERNULL, NDRCALL, NDRSTRUCT, NDRUNION, NDRPOINTER, NDRUniConformantArray
from aiosmb.dcerpc.v5.ndr import NDRVaryingString

from aiosmb.dcerpc.v5.rpcrt import DCERPCException
from aiosmb.dcerpc.v5 import system_errors
from aiosmb.dcerpc.v5.uuid import uuidtup_to_bin
from aiosmb.dcerpc.v5.structure import Structure

# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/4a25b8e1-fd90-41b6-9301-62ed71334436

MSRPC_UUID_EFSR = uuidtup_to_bin(('c681d488-d850-11d0-8c52-00c04fd90f7e', '1.0'))
#r"\PIPE\efsrpc",

class DCERPCSessionError(DCERPCException):
	def __init__(self, error_string=None, error_code=None, packet=None):
		DCERPCException.__init__(self, error_string, error_code, packet)

	def __str__( self ):
		key = self.error_code
		if key in system_errors.ERROR_MESSAGES:
			error_msg_short = system_errors.ERROR_MESSAGES[key][0]
			error_msg_verbose = system_errors.ERROR_MESSAGES[key][1] 
			return 'EFSR SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
		else:
			return 'EFSR SessionError: unknown error code: 0x%x' % self.error_code





################################################################################
# STRUCTURES
################################################################################

class EXIMPORT_CONTEXT_HANDLE(NDRSTRUCT): #guessing?
	structure = (
		('Data', '20s=""'),
	)

class PEXIMPORT_CONTEXT_HANDLE(NDRPOINTER):
    referent = (
        ('Data', EXIMPORT_CONTEXT_HANDLE),
    )

class EFS_RPC_BLOB(NDRSTRUCT):
	structure = (
		('Data', DWORD),
		('cbData', PCHAR),
	)

class PEFS_RPC_BLOB(NDRPOINTER):
	referent = (
		('Data', EFS_RPC_BLOB),
	)

class EFS_HASH_BLOB(NDRSTRUCT):
	structure = (
		('Data', DWORD),
		('cbData', PCHAR),
	)

class ENCRYPTION_CERTIFICATE_HASH(NDRSTRUCT):
	structure = (
		('Lenght', DWORD),
		('SID', RPC_SID),
		('Hash', EFS_HASH_BLOB),
		('Display', LPWSTR),
	)

class PENCRYPTION_CERTIFICATE_HASH(NDRPOINTER):
	referent = (
		('Data', ENCRYPTION_CERTIFICATE_HASH),
	)

class ENCRYPTION_CERTIFICATE_HASH_LIST(NDRSTRUCT):
	structure = (
		('nCert_Hash', DWORD),
		('SID', PENCRYPTION_CERTIFICATE_HASH),
	)
	
class PENCRYPTION_CERTIFICATE_HASH_LIST(NDRPOINTER):
	referent = (
		('Data', ENCRYPTION_CERTIFICATE_HASH_LIST),
	)

class CERTIFICATE_BLOB(NDRSTRUCT):
	structure = (
		('dwCertEncodingType', DWORD),
		('cbData', DWORD),
		('bData', PCHAR),
	)

class ENCRYPTION_CERTIFICATE(NDRSTRUCT):
	structure = (
		('cbTotalLength', DWORD),
		('UserSid', RPC_SID),
		('CertBlob', CERTIFICATE_BLOB),
	)

class PENCRYPTION_CERTIFICATE(NDRPOINTER):
	referent = (
		('Data', ENCRYPTION_CERTIFICATE),
	)

class ENCRYPTION_CERTIFICATE_LIST(NDRSTRUCT):
	structure = (
		('nUsers', DWORD),
		('Users', PENCRYPTION_CERTIFICATE),
	)

class PENCRYPTION_CERTIFICATE_LIST(NDRPOINTER):
	referent = (
		('Data', ENCRYPTION_CERTIFICATE_LIST),
	)

class ENCRYPTED_FILE_METADATA_SIGNATURE(NDRSTRUCT):
	structure = (
		('dwEfsAccessType', DWORD),
		('CertificatesAdded', PENCRYPTION_CERTIFICATE_HASH_LIST),
		('EncryptionCertificate', PENCRYPTION_CERTIFICATE),
		('EfsStreamSignature', PEFS_RPC_BLOB),
	)

class ENCRYPTION_PROTECTOR(NDRSTRUCT):
	structure = (
		('cbTotalLength', DWORD),
		('UserSid', RPC_SID),
		('ProtectorDescriptor', PWCHAR),
	)

class PENCRYPTION_PROTECTOR(NDRPOINTER):
	referent = (
		('Data', ENCRYPTION_PROTECTOR),
	)

class ENCRYPTION_PROTECTOR_LIST(NDRSTRUCT):
	structure = (
		('nProtectors', DWORD),
		('Protectors', PENCRYPTION_PROTECTOR),
	)

################################################################################
# Structure defs
################################################################################




################################################################################
# RPC CALLS
################################################################################
class RpcEfsRpcOpenFileRaw(NDRCALL):
	opnum = 0
	structure = (
		('FileName', WSTR),
		('Flags', LONG),
	)

class RpcEfsRpcOpenFileRawResponse(NDRCALL):
	structure = (
		('hContext', PEXIMPORT_CONTEXT_HANDLE),
	)

class RpcEfsRpcEncryptFileSrv(NDRCALL):
	opnum = 4
	structure = (
		('FileName', WSTR),
	)

class RpcEfsRpcEncryptFileSrvResponse(NDRCALL):
	structure = (
	)

class RpcEfsRpcDecryptFileSrv(NDRCALL):
	opnum = 5
	structure = (
		('FileName', WSTR),
		('OpenFlag', ULONG),
	)

class RpcEfsRpcQueryUsersOnFile(NDRCALL):
	opnum = 6
	structure = (
		('FileName', WSTR),
	)

class RpcEfsRpcQueryUsersOnFileResponse(NDRCALL):
	structure = (
		('ProtectorList', PENCRYPTION_CERTIFICATE_HASH_LIST),
	)

class RpcEfsRpcDecryptFileSrvResponse(NDRCALL):
	structure = (
	)

class EfsRpcQueryRecoveryAgents(NDRCALL):
	opnum = 7
	structure = (
		('FileName', WSTR),
	)

class EfsRpcQueryRecoveryAgentsResponse(NDRCALL):
	structure = (
		('ProtectorList', PENCRYPTION_CERTIFICATE_HASH_LIST),
	)

class RpcEfsRpcRemoveUsersFromFile(NDRCALL):
	opnum = 8
	structure = (
		('FileName', WSTR),
		('EncryptionCertificates', ENCRYPTION_CERTIFICATE_LIST)
	)

class RpcEfsRpcRemoveUsersFromFileResponse(NDRCALL):
	structure = (
		#? empty
	)

class RpcEfsRpcAddUsersToFile(NDRCALL):
	opnum = 9
	structure = (
		('FileName', WSTR),
		('EncryptionCertificates', ENCRYPTION_CERTIFICATE_LIST)
	)

class RpcEfsRpcAddUsersToFileResponse(NDRCALL):
	structure = (
		#? empty
	)

class RpcEfsRpcFileKeyInfo(NDRCALL):
	opnum = 12
	structure = (
		('FileName', WSTR),
		('InfoClass', DWORD),
	)

class RpcEfsRpcFileKeyInfoResponse(NDRCALL):
	structure = (
		('KeyInfo', PEFS_RPC_BLOB),
	)

class RpcEfsRpcDuplicateEncryptionInfoFile(NDRCALL):
	opnum = 13
	structure = (
		('SrcFileName', WSTR),
		('DestFileName', WSTR),
		('dwCreationDisposition', DWORD),
		('dwAttributes', DWORD),
		('RelativeSD', EFS_RPC_BLOB),
		('bInheritHandle', BOOL),
	)

class RpcEfsRpcDuplicateEncryptionInfoFileResponse(NDRCALL):
	structure = (
		#? empty
	)

class RpcEfsRpcAddUsersToFileEx(NDRCALL):
	opnum = 15
	structure = (
		('dwFlags', DWORD),
		('Reserved', NDRPOINTERNULL),
		('FileName', WSTR),
		('EncryptionCertificates', ENCRYPTION_CERTIFICATE_LIST),
	)

class RpcEfsRpcAddUsersToFileExResponse(NDRCALL):
	structure = (
		#? empty
	)

################################################################################
# OPNUMs and their corresponding structures
################################################################################
OPNUMS = {
	0  : (RpcEfsRpcOpenFileRaw, RpcEfsRpcOpenFileRawResponse),
	4  : (RpcEfsRpcEncryptFileSrv, RpcEfsRpcEncryptFileSrvResponse),
	5  : (RpcEfsRpcDecryptFileSrv, RpcEfsRpcDecryptFileSrvResponse),
	6  : (RpcEfsRpcQueryUsersOnFile, RpcEfsRpcQueryUsersOnFileResponse),
	7  : (EfsRpcQueryRecoveryAgents, EfsRpcQueryRecoveryAgentsResponse),
	8  : (RpcEfsRpcRemoveUsersFromFile, RpcEfsRpcRemoveUsersFromFileResponse),
	9  : (RpcEfsRpcAddUsersToFile, RpcEfsRpcAddUsersToFileResponse),
	12 : (RpcEfsRpcFileKeyInfo, RpcEfsRpcFileKeyInfoResponse),
	13 : (RpcEfsRpcDuplicateEncryptionInfoFile, RpcEfsRpcDuplicateEncryptionInfoFileResponse),
	15 : (RpcEfsRpcAddUsersToFileEx, RpcEfsRpcAddUsersToFileExResponse),

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

async def hRpcEfsRpcAddUsersToFile(dce, FileName):
	request = RpcEfsRpcAddUsersToFile()
	request['FileName'] = checkNullString(FileName)
	return await dce.request(request)


async def hRpcEfsRpcAddUsersToFileEx(dce, FileName, dwFlags = 2, EncryptionCertificates = NULL):
	request = RpcEfsRpcAddUsersToFileEx()
	request['dwFlags'] = dwFlags
	request['FileName'] = checkNullString(FileName)
	request['EncryptionCertificates'] = EncryptionCertificates
	
	return await dce.request(request)

async def hRpcEfsRpcDecryptFileSrv(dce, FileName, OpenFlag=0):
	request = RpcEfsRpcDecryptFileSrv()
	request['FileName'] = checkNullString(FileName)
	request['OpenFlag'] = OpenFlag
	return await dce.request(request)

async def hRpcEfsRpcEncryptFileSrv(dce, FileName):
	request = RpcEfsRpcEncryptFileSrv()
	request['FileName'] = checkNullString(FileName)
	return await dce.request(request)

async def hRpcEfsRpcDuplicateEncryptionInfoFile(dce, FileName, dwCreationDisposition = 0, dwAttributes = 0, RelativeSD = NULL, bInheritHandle = 0):
	request = RpcEfsRpcDuplicateEncryptionInfoFile()
	request['SrcFileName'] = checkNullString(FileName)
	request['DestFileName'] = checkNullString(FileName)
	request['dwCreationDisposition'] = dwCreationDisposition
	request['dwAttributes'] = dwAttributes
	if RelativeSD is not NULL:
		request['RelativeSD'] = RelativeSD
	else:
		request['RelativeSD'] = EFS_RPC_BLOB()
	request['bInheritHandle'] = bInheritHandle	
	return await dce.request(request)

async def hRpcEfsRpcFileKeyInfo(dce, FileName, InfoClass = 0):
	request = RpcEfsRpcFileKeyInfo()
	request['FileName'] = checkNullString(FileName)
	request['InfoClass'] = InfoClass
	return await dce.request(request)

async def hRpcEfsRpcOpenFileRaw(dce, FileName, Flags = 0):
	request = RpcEfsRpcOpenFileRaw()
	request['FileName'] = checkNullString(FileName)
	request['Flags'] = Flags
	return await dce.request(request)

async def hRpcEfsRpcQueryRecoveryAgents(dce, FileName):
	request = EfsRpcQueryRecoveryAgents()
	request['FileName'] = checkNullString(FileName)
	return await dce.request(request)

async def hRpcEfsRpcQueryUsersOnFile(dce, FileName):
	request = RpcEfsRpcQueryUsersOnFile()
	request['FileName'] = checkNullString(FileName)
	return await dce.request(request)

async def hRpcEfsRpcRemoveUsersFromFile(dce, FileName, EncryptionCertificates = NULL):
	request = RpcEfsRpcRemoveUsersFromFile()
	request['FileName'] = checkNullString(FileName)
	request['EncryptionCertificates'] = EncryptionCertificates
	return await dce.request(request)