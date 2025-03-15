

import io
from os import stat

from aiosmb.dcerpc.v5.dtypes import GUID, LONG, BOOL, PWCHAR, RPC_SID, PCHAR, ULONGLONG, UINT, USHORT, LPWSTR, DWORD, ULONG, NULL, WSTR, PBOOL, PLONG
from aiosmb.dcerpc.v5.ndr import NDRPOINTERNULL, NDRCALL, NDRSTRUCT, NDRUNION, NDRPOINTER, NDRUniConformantArray
from aiosmb.dcerpc.v5.ndr import NDRVaryingString

from aiosmb.dcerpc.v5.rpcrt import DCERPCException
from aiosmb.dcerpc.v5 import system_errors
from aiosmb.dcerpc.v5.uuid import uuidtup_to_bin
from aiosmb.dcerpc.v5.structure import Structure

# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsnm/b471e023-618d-4c48-877f-f30c3005320c

MSRPC_UUID_DFSNM = uuidtup_to_bin(('4fc742e0-4a10-11cf-8273-00aa004ae673', '3.0'))
#r"\PIPE\netdfs",

class DCERPCSessionError(DCERPCException):
	def __init__(self, error_string=None, error_code=None, packet=None):
		DCERPCException.__init__(self, error_string, error_code, packet)

	def __str__( self ):
		key = self.error_code
		if key in system_errors.ERROR_MESSAGES:
			error_msg_short = system_errors.ERROR_MESSAGES[key][0]
			error_msg_verbose = system_errors.ERROR_MESSAGES[key][1] 
			return 'DFSNM SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
		else:
			return 'DFSNM SessionError: unknown error code: 0x%x' % self.error_code



NET_API_STATUS = DWORD
NETDFS_SERVER_OR_DOMAIN_HANDLE = LPWSTR

#DFS_TARGET_PRIORITY_CLASS
DfsInvalidPriorityClass = -1
DfsSiteCostNormalPriorityClass = 0
DfsGlobalHighPriorityClass     = 1
DfsSiteCostHighPriorityClass   = 2
DfsSiteCostLowPriorityClass    = 3
DfsGlobalLowPriorityClass      = 4

DFS_NAMESPACE_VERSION_ORIGIN_COMBINED = 0                                                
DFS_NAMESPACE_VERSION_ORIGIN_SERVER = 1
DFS_NAMESPACE_VERSION_ORIGIN_DOMAIN = 2

################################################################################
# STRUCTURES
################################################################################

class DFS_TARGET_PRIORITY(NDRSTRUCT):
	structure = (
		('TargetPriorityClass', ULONG),
		('TargetPriorityRank', USHORT),
		('Reserved', USHORT),
	)

class DFS_STORAGE_INFO(NDRSTRUCT):
	structure = (
		('ServerName', WSTR),
		('ShareName', WSTR),
	)
	
class DFS_STORAGE_INFO_ARRAY(NDRUniConformantArray):
	item = DFS_STORAGE_INFO
	
class DFS_STORAGE_INFO_1(NDRSTRUCT):
	structure = (
		('State', ULONG),
		('ServerName', WSTR),
		('ShareName', WSTR),
		('TargetPriority', DFS_TARGET_PRIORITY),
	)

class DFS_STORAGE_INFO_1_ARRAY(NDRUniConformantArray):
	item = DFS_STORAGE_INFO_1
	
class DFSM_ROOT_LIST_ENTRY(NDRSTRUCT):
	structure = (
		('ServerShare', WSTR),
	)

class DFSM_ROOT_LIST_ENTRY_ARRAY(NDRUniConformantArray):
	item = DFSM_ROOT_LIST_ENTRY
	
class DFSM_ROOT_LIST(NDRSTRUCT):
	structure = (
		('cEntries', ULONG),
		('Entry', NDRUniConformantArray),
	)

class DFS_SUPPORTED_NAMESPACE_VERSION_INFO(NDRSTRUCT):
	structure = (
		('DomainDfsMajorVersion', ULONG),
		('DomainDfsMinorVersion', ULONG),
		('DomainDfsCapabilities', ULONGLONG),
		('StandaloneDfsMajorVersion', ULONG),
		('StandaloneDfsMinorVersion', ULONG),
		('StandaloneDfsCapabilities', ULONGLONG),
	)

class DFS_INFO_1(NDRSTRUCT):
	structure = (
		('EntryPath', WSTR),
	)
	
class DFS_INFO_2(NDRSTRUCT):
	structure = (
		('EntryPath', WSTR),
		('Comment', WSTR),
		('State', DWORD),
		('NumberOfStorages', DWORD),
	)

class DFS_INFO_3(NDRSTRUCT):
	structure = (
		('EntryPath', WSTR),
		('Comment', WSTR),
		('State', DWORD),
		('NumberOfStorages', DWORD),
		('Storage', DFS_STORAGE_INFO_ARRAY),
	)
	
class DFS_INFO_4(NDRSTRUCT):
	structure = (
		('EntryPath', WSTR),
		('Comment', WSTR),
		('State', DWORD),
		('Timeout', ULONG),
		('Guid', GUID),
		('NumberOfStorages', DWORD),
		('Storage', DFS_STORAGE_INFO_ARRAY),
	)
	
class DFS_INFO_5(NDRSTRUCT):
	structure = (
		('EntryPath', WSTR),
		('Comment', WSTR),
		('State', DWORD),
		('Timeout', ULONG),
		('Guid', GUID),
		('PropertyFlags', ULONG),
		('MetadataSize', ULONG),
		('NumberOfStorages', DWORD),
	)
	
class DFS_INFO_6(NDRSTRUCT):
	structure = (
		('EntryPath', WSTR),
		('Comment', WSTR),
		('State', DWORD),
		('Timeout', ULONG),
		('Guid', GUID),
		('PropertyFlags', ULONG),
		('MetadataSize', ULONG),
		('NumberOfStorages', DWORD),
		('Storage', DFS_STORAGE_INFO_1_ARRAY),
	)

class DFS_INFO_7(NDRSTRUCT):
	structure = (
		('GenerationGuid', GUID),
	)
	
# .. other structures




################################################################################
# Structure defs
################################################################################




################################################################################
# RPC CALLS
################################################################################
class RpcNetrDfsAddStdRoot(NDRCALL):
	opnum = 12
	structure = (
		('ServerName', WSTR),
		('RootShare', WSTR),
		('Comment', WSTR),
		('ApiFlags', ULONG),
	)

class RpcNetrDfsAddStdRootResponse(NDRCALL):
	structure = (
	)
	
class NetrDfsRemoveStdRoot(NDRCALL):
	opnum = 13
	structure = (
		('ServerName', WSTR),
		('RootShare', WSTR),
		('ApiFlags', ULONG),
	)

class NetrDfsRemoveStdRootResponse(NDRCALL):
	structure = (
	)

################################################################################
# OPNUMs and their corresponding structures
################################################################################
OPNUMS = {
	12  : (RpcNetrDfsAddStdRoot, RpcNetrDfsAddStdRootResponse),
	13  : (NetrDfsRemoveStdRoot, NetrDfsRemoveStdRoot),
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

async def hRpcNetrDfsAddStdRoot(dce, ServerName, RootShare, Comment = NULL, ApiFlags = 0):
	request = RpcNetrDfsAddStdRoot()
	request['ServerName'] = checkNullString(ServerName)
	request['RootShare'] = checkNullString(RootShare)
	request['Comment'] = checkNullString(Comment)
	request['ApiFlags'] = ApiFlags
	return await dce.request(request)

async def hNetrDfsRemoveStdRoot(dce, ServerName, RootShare, ApiFlags = 0):
	request = NetrDfsRemoveStdRoot()
	request['ServerName'] = checkNullString(ServerName)
	request['RootShare'] = checkNullString(RootShare)
	request['ApiFlags'] = ApiFlags
	return await dce.request(request)