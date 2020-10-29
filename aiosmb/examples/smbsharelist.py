
import asyncio
from aiosmb.commons.connection.url import SMBConnectionURL
from aiosmb.commons.interfaces.machine import SMBMachine

async def test(url_str):

	url = SMBConnectionURL(url_str)
	connection = url.get_connection()
	_, err = await connection.login()
	if err is not None:
		print(err)
		raise err
	machine = SMBMachine(connection)
	async for share, err in  machine.list_shares():
		if err is not None:
			print(err)
			raise err
		
		print(share)

	


if __name__ == '__main__':
	url = 'smb2+ntlm-password://TEST\\Administrator:QLFbT8zkiFGlJuf0B3Qq@10.10.10.2'
	asyncio.run(test(url))