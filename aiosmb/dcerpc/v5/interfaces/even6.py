
import asyncio
import os
from aiosmb.dcerpc.v5.common.connection.smbdcefactory import SMBDCEFactory
from aiosmb.commons.utils.extb import pprint_exc
from aiosmb.commons.utils.decorators import red_gen, red, rr
from aiosmb.dcerpc.v5 import even6
from aiosmb.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_NONE, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, DCERPCException, RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_CONNECT



class SMBEven6:
	def __init__(self, connection):
		self.connection = connection
		self.service_manager = None
		
		self.dce = None
		
	async def __aenter__(self):
		return self
		
	async def __aexit__(self, exc_type, exc, traceback):
		await self.close()
		return True,None
	
	@red
	async def close(self):
		if self.dce:
			try:
				await self.dce.disconnect()
			except:
				pass
			return
		
		return True,None
	
	async def connect(self, open = True):
		rpctransport = SMBDCEFactory(self.connection, filename=r'\eventlog')
		
		self.dce = rpctransport.get_dce_rpc()
		self.dce.set_auth_level(RPC_C_AUTHN_LEVEL_CONNECT)
		_, err = await self.dce.connect()
		if err is not None:
			return False, err
		_, err = await self.dce.bind(even6.MSRPC_UUID_EVEN6)
		if err is not None:
			return False, err

		return True,None

	
	async def register_query(self, path, query = '*\x00', flags = even6.EvtQueryChannelName | even6.EvtReadNewestToOldest):
		try:
			res, err = await even6.hEvtRpcRegisterLogQuery(self.dce, path, flags, query = query)
			if err is not None:
				raise err
			
			return res, None
		
		except Exception as e:
			return None, err

async def amain():
	from aiosmb.commons.connection.url import SMBConnectionURL
	from aiosmb.connection import SMBConnection

	url = 'smb2+kerberos-password://TEST\\Administrator:QLFbT8zkiFGlJuf0B3Qq@win2019ad.test.corp?serverip=10.10.10.2&dc=10.10.10.2'
	su = SMBConnectionURL(url)
	conn = su.get_connection()

	_, err = await conn.login()
	if err is not None:
		print(err)
		return
	else:
		print('SMB Connected!')
	ei = SMBEven6(conn)
	_, err = await ei.connect()
	if err is not None:
		print(err)
		return
	print('DCE Connected!')
	res, err = await ei.register_query("Securasdfadsfadsfity1")
	if err is not None:
		print(err)

	else:
		print(res)




if __name__ == '__main__':
	asyncio.run(amain())