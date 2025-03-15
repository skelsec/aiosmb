from aiosmb import logger

from aiosmb.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_NONE,\
	RPC_C_AUTHN_LEVEL_CONNECT,\
	RPC_C_AUTHN_LEVEL_CALL,\
	RPC_C_AUTHN_LEVEL_PKT,\
	RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,\
	RPC_C_AUTHN_LEVEL_PKT_PRIVACY

from aiosmb.dcerpc.v5.interfaces import InterfaceManager, InterfaceEndpoint
from aiosmb.dcerpc.v5.dtypes import NULL
from aiosmb.dcerpc.v5.efsr import MSRPC_UUID_EFSR, hRpcEfsRpcAddUsersToFile, hRpcEfsRpcAddUsersToFileEx,\
	hRpcEfsRpcDecryptFileSrv, hRpcEfsRpcEncryptFileSrv, hRpcEfsRpcDuplicateEncryptionInfoFile,\
	hRpcEfsRpcFileKeyInfo, hRpcEfsRpcOpenFileRaw, hRpcEfsRpcQueryRecoveryAgents, hRpcEfsRpcQueryUsersOnFile,\
	hRpcEfsRpcRemoveUsersFromFile
# Requires Encrypting File System service running on the target

class EFSRRPC(InterfaceManager):
	def __init__(self, connection, endpoint):
		super().__init__(connection, endpoint)

	@classmethod
	def endpoints(cls):
		return [
			InterfaceEndpoint('ncan_np', "df1941c5-fe89-4e79-bf10-463657acf44d", "1.0", pipename=r"\efsrpc", authlevel=RPC_C_AUTHN_LEVEL_PKT_PRIVACY),
			InterfaceEndpoint('ncan_np', "c681d488-d850-11d0-8c52-00c04fd90f7e", "1.0", pipename=r"\lsarpc", authlevel=RPC_C_AUTHN_LEVEL_PKT_PRIVACY),
			InterfaceEndpoint('ncan_np', "c681d488-d850-11d0-8c52-00c04fd90f7e", "1.0", pipename=r"\samr", authlevel=RPC_C_AUTHN_LEVEL_PKT_PRIVACY),
			InterfaceEndpoint('ncan_np', "c681d488-d850-11d0-8c52-00c04fd90f7e", "1.0", pipename=r"\lsass", authlevel=RPC_C_AUTHN_LEVEL_PKT_PRIVACY),
			InterfaceEndpoint('ncan_np', "c681d488-d850-11d0-8c52-00c04fd90f7e", "1.0", pipename=r"\netlogon", authlevel=RPC_C_AUTHN_LEVEL_PKT_PRIVACY),
			InterfaceEndpoint('ncacn_ip_tcp', "df1941c5-fe89-4e79-bf10-463657acf44d", "1.0", authlevel=RPC_C_AUTHN_LEVEL_PKT_PRIVACY),
			InterfaceEndpoint('ncacn_ip_tcp', "c681d488-d850-11d0-8c52-00c04fd90f7e", "1.0", authlevel=RPC_C_AUTHN_LEVEL_PKT_PRIVACY),
		]
	
	@staticmethod
	def create_instance(connection, endpoint):
		return EFSRRPC(connection, endpoint)
	
	async def cleanup(cls):
		pass
	
	async def hRpcEfsRpcAddUsersToFile(self, fileName):
		return await hRpcEfsRpcAddUsersToFile(self.dce, fileName)
	
	async def hRpcEfsRpcAddUsersToFileEx(self, fileName):
		return await hRpcEfsRpcAddUsersToFileEx(self.dce, fileName)
	
	async def hRpcEfsRpcDecryptFileSrv(self, fileName, openFlag = 0):
		return await hRpcEfsRpcDecryptFileSrv(self.dce, fileName, openFlag)
	
	async def hRpcEfsRpcEncryptFileSrv(self, fileName):
		return await hRpcEfsRpcEncryptFileSrv(self.dce, fileName)
	
	async def hRpcEfsRpcDuplicateEncryptionInfoFile(self, srcFileName, dstFileName):
		return await hRpcEfsRpcDuplicateEncryptionInfoFile(self.dce, srcFileName, dstFileName)
	
	async def hRpcEfsRpcFileKeyInfo(self, fileName, infoClass = 0):
		return await hRpcEfsRpcFileKeyInfo(self.dce, fileName, infoClass)

	async def hRpcEfsRpcOpenFileRaw(self, fileName, flags = 0):
		return await hRpcEfsRpcOpenFileRaw(self.dce, fileName, flags)
	
	async def hRpcEfsRpcQueryRecoveryAgents(self, fileName):
		return await hRpcEfsRpcQueryRecoveryAgents(self.dce, fileName)
	
	async def hRpcEfsRpcQueryUsersOnFile(self, fileName):
		return await hRpcEfsRpcQueryUsersOnFile(self.dce, fileName)
	
	async def hRpcEfsRpcRemoveUsersFromFile(self, fileName, EncryptionCertificates = None):
		return await hRpcEfsRpcRemoveUsersFromFile(self.dce, fileName, EncryptionCertificates if EncryptionCertificates is not None else NULL)

async def amain():
	try:
		host = '192.168.56.22'
		user = 'hodor'
		password = 'hodor'
		domain = None

		for endpoint in EFSRRPC.endpoints():
			rpc, err = await EFSRRPC.from_ntlm_params(host, user, password, domain, endpoint=endpoint)
			if err is not None:
				print('Failed to connect to %s' % str(endpoint))
				continue
			print(rpc)
			async with rpc:
				print(1)
				res, err = await rpc.hRpcEfsRpcAddUsersToFile('\\\\192.168.56.129\\C$\\alma')
				if err is not None:
					print('hRpcEfsRpcAddUsersToFile failed Reason: %s' % err)
				res, err = await rpc.hRpcEfsRpcAddUsersToFile('\\\\192.168.56.129\\C$\\alma')
				if err is not None:
					print('hRpcEfsRpcAddUsersToFile failed Reason: %s' % err)

				res, err = await rpc.hRpcEfsRpcAddUsersToFileEx('\\\\192.168.56.129\\C$\\alma')
				if err is not None:
					print('hRpcEfsRpcAddUsersToFileEx failed Reason: %s' % err)
				res, err = await rpc.hRpcEfsRpcDecryptFileSrv('\\\\192.168.56.129\\C$\\alma')
				if err is not None:
					print('hRpcEfsRpcDecryptFileSrv failed Reason: %s' % err)
				res, err = await rpc.hRpcEfsRpcEncryptFileSrv('\\\\192.168.56.129\\C$\\alma')
				if err is not None:
					print('hRpcEfsRpcEncryptFileSrv failed Reason: %s' % err)
				res, err = await rpc.hRpcEfsRpcDuplicateEncryptionInfoFile('\\\\192.168.56.129\\C$\\alma', '\\\\192.168.56.129\\C$\\alma')
				if err is not None:
					print('hRpcEfsRpcDuplicateEncryptionInfoFile failed Reason: %s' % err)
				res, err = await rpc.hRpcEfsRpcFileKeyInfo('\\\\192.168.56.129\\C$\\alma')
				if err is not None:
					print('hRpcEfsRpcFileKeyInfo failed Reason: %s' % err)
				res, err = await rpc.hRpcEfsRpcOpenFileRaw('\\\\192.168.56.129\\C$\\alma')
				if err is not None:
					print('hRpcEfsRpcOpenFileRaw failed Reason: %s' % err)
				res, err = await rpc.hRpcEfsRpcQueryRecoveryAgents('\\\\192.168.56.129\\C$\\alma')
				if err is not None:
					print('hRpcEfsRpcQueryRecoveryAgents failed Reason: %s' % err)
				res, err = await rpc.hRpcEfsRpcQueryUsersOnFile('\\\\192.168.56.129\\C$\\alma')
				if err is not None:
					print('hRpcEfsRpcQueryUsersOnFile failed Reason: %s' % err)
					#raise err
				res, err = await rpc.hRpcEfsRpcRemoveUsersFromFile('\\\\192.168.56.129\\C$\\alma')
				if err is not None:
					print('hRpcEfsRpcRemoveUsersFromFile failed Reason: %s' % err)
				print(res)
		print(5)
	except Exception as e:
		print(e)
		import traceback
		traceback.print_exc()

if __name__ == '__main__':
	import asyncio
	
	asyncio.run(amain())