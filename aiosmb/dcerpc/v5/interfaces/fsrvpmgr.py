from aiosmb import logger

from aiosmb.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_NONE,\
	RPC_C_AUTHN_LEVEL_CONNECT,\
	RPC_C_AUTHN_LEVEL_CALL,\
	RPC_C_AUTHN_LEVEL_PKT,\
	RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,\
	RPC_C_AUTHN_LEVEL_PKT_PRIVACY

from aiosmb.dcerpc.v5.interfaces import InterfaceManager, InterfaceEndpoint
from aiosmb.dcerpc.v5.fsrvp import hRpcIsPathSupported, hRpcIsPathShadowCopied
		
class FSRVPRPC(InterfaceManager):
	def __init__(self, connection, endpoint):
		super().__init__(connection, endpoint)

	@classmethod
	def endpoints(cls):
		return [
			InterfaceEndpoint('ncan_np', "a8e0653c-2744-4389-a61d-7373df8b2292", "1.0", pipename=r"\FssagentRpc", authlevel=RPC_C_AUTHN_LEVEL_PKT_PRIVACY),
			InterfaceEndpoint('ncacn_ip_tcp', "a8e0653c-2744-4389-a61d-7373df8b2292", "1.0", authlevel=RPC_C_AUTHN_LEVEL_PKT_PRIVACY),
		]
	
	@staticmethod
	def create_instance(connection, endpoint):
		return FSRVPRPC(connection, endpoint)
	
	async def cleanup(cls):
		pass

	async def hRpcIsPathSupported(self, path):
		return await hRpcIsPathSupported(self.dce, path)
	
	async def hRpcIsPathShadowCopied(self, path):
		return await hRpcIsPathShadowCopied(self.dce, path)


async def amain():
	host = '192.168.56.11'
	user = 'vagrant'
	password = 'vagrant'
	domain = 'NORTH'


	rpc, err = await FSRVPRPC.from_ntlm_params(host, user, password, domain)
	if err is not None:
		raise err
	print(rpc)
	async with rpc:
		print(1)

if __name__ == '__main__':
	import asyncio
	
	asyncio.run(amain())