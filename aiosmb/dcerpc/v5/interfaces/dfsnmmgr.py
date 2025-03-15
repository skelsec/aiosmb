from aiosmb.dcerpc.v5.common.connection.smbdcefactory import SMBDCEFactory
from aiosmb.dcerpc.v5 import wkst
from aiosmb.dcerpc.v5.interfaces.endpointmgr import EPM
from aiosmb.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
from aiosmb.wintypes.ntstatus import NTStatus
from aiosmb import logger
from aiosmb.dcerpc.v5.dtypes import NULL
from aiosmb.dcerpc.v5.interfaces.endpointmgr import EPM
from aiosmb.connection import SMBConnection
from aiosmb.dcerpc.v5.connection import DCERPC5Connection
from aiosmb.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_NONE,\
	RPC_C_AUTHN_LEVEL_CONNECT,\
	RPC_C_AUTHN_LEVEL_CALL,\
	RPC_C_AUTHN_LEVEL_PKT,\
	RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,\
	RPC_C_AUTHN_LEVEL_PKT_PRIVACY,\
	DCERPCException, RPC_C_AUTHN_GSS_NEGOTIATE

from aiosmb.dcerpc.v5.interfaces import InterfaceManager, InterfaceEndpoint
from aiosmb.dcerpc.v5.dfsnm import MSRPC_UUID_DFSNM, hRpcNetrDfsAddStdRoot, hNetrDfsRemoveStdRoot


class DFSNMRPC(InterfaceManager):
	def __init__(self, connection, endpoint):
		super().__init__(connection, endpoint)
	
	@classmethod
	def endpoints(cls):
		return [
			InterfaceEndpoint('ncan_np', "4fc742e0-4a10-11cf-8273-00aa004ae673", "3.0", pipename=r"\netdfs", authlevel=RPC_C_AUTHN_LEVEL_NONE),
			InterfaceEndpoint('ncacn_ip_tcp', "4fc742e0-4a10-11cf-8273-00aa004ae673", "3.0", authlevel=RPC_C_AUTHN_LEVEL_NONE),
		]
	
	@staticmethod
	def create_instance(connection, endpoint):
		return DFSNMRPC(connection, endpoint)
	
	async def cleanup(cls):
		pass
	
	async def hRpcNetrDfsAddStdRoot(self, serverName, rootShare, comment = NULL, flags = 0):
		return await hRpcNetrDfsAddStdRoot(self.dce, serverName, RootShare=rootShare, Comment=comment, ApiFlags=flags)
	
	async def hNetrDfsRemoveStdRoot(self, serverName, rootShare, flags = 0):
		return await hNetrDfsRemoveStdRoot(self.dce, serverName, RootShare=rootShare, ApiFlags=flags)


async def amain():
	host = '192.168.56.11'
	user = 'hodor'
	password = 'hodor'
	domain = 'NORTH'


	rpc, err = await DFSNMRPC.from_ntlm_params(host, user, password, domain)
	if err is not None:
		raise err
	print(rpc)
	async with rpc:
		print(1)
		#res, err = await rpc.hRpcNetrDfsAddStdRoot('\\\\192.168.56.129\\alma\\aaa', 'aaa', 'aaa', 0)
		#if err is not None:
		#	raise err
		res, err = await rpc.hNetrDfsRemoveStdRoot('\\\\192.168.56.129/aaa\\share\\file.txt', 'aaa', 0)
		if err is not None:
			raise err
		print(res)

if __name__ == '__main__':
	import asyncio
	
	asyncio.run(amain())