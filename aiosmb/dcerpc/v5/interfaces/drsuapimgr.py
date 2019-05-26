
from aiosmb.dcerpc.v5.transport.smbtransport import SMBTransport
from aiosmb.dcerpc.v5.transport.factory import DCERPCTransportFactory
from aiosmb.dcerpc.v5 import epm, drsuapi
from aiosmb.dcerpc.v5.interfaces.servicemanager import *
from aiosmb.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY, DCERPCException, RPC_C_AUTHN_GSS_NEGOTIATE
		
class SMBDRSUAPI:
	def __init__(self, connection):
		self.connection = connection	
		self.dce = None
		self.handle = None
		
	async def __aenter__(self):
		return self
		
	async def __aexit__(self, exc_type, exc, traceback):
		await self.close()
		
	async def connect(self, open = False):
		stringBinding = await epm.hept_map(self.connection.target.get_ip(), drsuapi.MSRPC_UUID_DRSUAPI, protocol='ncacn_ip_tcp')
		print(stringBinding)
		rpc = DCERPCTransportFactory(stringBinding)
		
		rpc.setRemoteHost(self.connection.target.get_ip())
		rpc.setRemoteName(self.connection.target.get_ip())
		self.dce = rpc.get_dce_rpc()
		self.dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
		#if self.__doKerberos:
		#	self.dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
		await self.dce.connect()
		print('WOW!')
		await self.dce.bind(drsuapi.MSRPC_UUID_DRSUAPI)
		print('WOW2!')
	
	async def open(self):
		if not self.dce:
			await self.connect()
		
		ans = await rrp.hOpenLocalMachine(self.dce)
		self.handle = ans['phKey']
		
	async def close(self):
		raise Exception('Not implemented!')