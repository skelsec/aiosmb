import asyncio
import logging

from aiosmb.dcerpc.v5.interfaces.drsuapimgr import SMBDRSUAPI
from aiosmb.commons.interfaces.machine import SMBMachine
from aiosmb.commons.connection.url import SMBConnectionURL

async def amain(url):
	print(1)
	conn_url = SMBConnectionURL(url)
	print(2)
	connection  = conn_url.get_connection()
	await connection.login()
	print(3)

	async with SMBMachine(connection) as computer:
		async with SMBDRSUAPI(connection, 'TEST') as drsuapi:
			try:
				_, err = await drsuapi.connect()
				_, err = await drsuapi.open()
				if err is not None:
					raise err

				async for username, user_sid, err in computer.list_domain_users(target_domain = 'TEST'):
					#print(username)

					x, err = await drsuapi.DRSCrackNames(name=username)
					if err is not None:
						raise err
					
					#print(x.dump())
					#await asyncio.sleep(0.01)
			
			except Exception as e:
				logging.exception('error!')
				raise e

def main(url):
	asyncio.run(amain(url))

if __name__ == '__main__':
	url = 'smb2+ntlm-password://TEST\\victim:Passw0rd!1@10.10.10.2'
	main(url)