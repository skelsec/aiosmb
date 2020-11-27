
import asyncio
import os
from aiosmb.dcerpc.v5.common.connection.smbdcefactory import SMBDCEFactory
from aiosmb.dcerpc.v5 import bkrp
from aiosmb.wintypes.ntstatus import NTStatus
from aiosmb.dcerpc.v5.rpcrt import DCERPCException
from aiosmb import logger
from aiosmb.commons.utils.extb import pprint_exc
from aiosmb.commons.utils.decorators import red_gen, red, rr
from aiosmb.dcerpc.v5.dtypes import NULL
from aiosmb.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_NONE, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, DCERPCException, RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_CONNECT

class SMBBKRP:
	def __init__(self, connection):
		self.connection = connection
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

	@red
	async def connect(self, open = True):
		rpctransport = SMBDCEFactory(self.connection, filename=r'\protected_storage')
		self.dce = rpctransport.get_dce_rpc()
		self.dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
		_, err = await self.dce.connect()
		if err is not None:
			return False, err
		_, err = await self.dce.bind(bkrp.MSRPC_UUID_BKRP)
		if err is not None:
			return False, err
		return True,None

	async def retrieve_backup_key(self):
		# Requests the public key part of the server's ClientWrap key pair.
		resp, err = await bkrp.hBackuprKey(self.dce, bkrp.BACKUPKEY_RETRIEVE_BACKUP_KEY_GUID, NULL)
		if err is not None:
			return None, err
		return b''.join(resp['ppDataOut']), None

	async def encrypt_data(self, data):
		resp, err = await bkrp.hBackuprKey(self.dce, bkrp.BACKUPKEY_BACKUP_GUID, data)
		if err is not None:
			return None, err
		return b''.join(resp['ppDataOut']), None

	async def decrypt_data(self, data):
		resp, err = await bkrp.hBackuprKey(self.dce, bkrp.BACKUPKEY_RESTORE_GUID, data)
		if err is not None:
			return None, err
		return b''.join(resp['ppDataOut']), None

	async def decrypt_data_2k(self, data):
		resp, err = await bkrp.hBackuprKey(self.dce, bkrp.BACKUPKEY_RESTORE_GUID_WIN2K, data)
		if err is not None:
			return None, err
		return b''.join(resp['ppDataOut']), None


async def amain(url):
	import traceback
	import hashlib
	from aiosmb.commons.connection.url import SMBConnectionURL
	from aiosmb.commons.interfaces.machine import SMBMachine

	url = SMBConnectionURL(url)
	connection = url.get_connection()
	_, err = await connection.login()
	if err is not None:
		print(err)
		raise err
	
	async with SMBBKRP(connection) as b:
		_, err = await b.connect()
		if err is not None:
			print(err)
			print(traceback.format_tb(err.__traceback__))
			return
		
		res, err = await b.retrieve_backup_key()
		if err is not None:
			print(err)
			print(traceback.format_tb(err.__traceback__))
			return
		print(res)
		print('!!!!!!!!!!!!!!!!!!!!!!!')
		res, err = await b.encrypt_data(b'HEELLO WORLD!')
		if err is not None:
			print(err)
			print(traceback.format_tb(err.__traceback__))
			return
		print(res)

		res, err = await b.decrypt_data(res)
		if err is not None:
			print(err)
			print(traceback.format_tb(err.__traceback__))
			return
		print(res)

if __name__ == '__main__':
	url = 'smb2+ntlm-password://TEST\\victim:Passw0rd!1@10.10.10.2'
	asyncio.run(amain(url))
	