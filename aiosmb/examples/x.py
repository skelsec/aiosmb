
import asyncio
from aiosmb.commons.connection.url import SMBConnectionURL


async def amain():
	url = 'smb2+ntlm-password://TEST\\Administrator:QLFbT8zkiFGlJuf0B3Qq@10.10.10.102/C$/Users/victim/Desktop/lsass.DMP'
	smburl = SMBConnectionURL(url)
	connection = smburl.get_connection()
	smbfile = smburl.get_file()

	async with connection:
		_, err = await connection.login()
		if err is not None:
			raise err
		
		_, err = await smbfile.open(connection)
		if err is not None:
			raise err
		
def main():
	asyncio.run(amain())

if __name__ == '__main__':
	main()