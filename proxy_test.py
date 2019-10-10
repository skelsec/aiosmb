import asyncio
import logging

from aiosmb.commons.smbcredential import SMBCredential
from aiosmb.commons.smbtarget import SMBTarget
from aiosmb.commons.smbtargetproxy import SMBTargetProxy
from aiosmb.smbconnection import SMBConnection
from aiosmb.filereader import SMBFileReader
from aiosmb.commons.authenticator_builder import AuthenticatorBuilder

async def filereader_test(connection_string, filename, proxy = None):
	target = SMBTarget.from_connection_string(connection_string)
	if proxy is not None:
		target.proxy = SMBTargetProxy.from_connection_string(proxy)
		print(str(target))
	
	credential = SMBCredential.from_connection_string(connection_string)
	
	spneg = AuthenticatorBuilder.to_spnego_cred(credential, target)
	
	async with SMBConnection(spneg, target) as connection: 
		await connection.login()
		
		async with SMBFileReader(connection) as reader:
			await reader.open(filename)
			data = await reader.read()
			print(data)
			"""
			await reader.seek(0,0)
			data = await reader.read()
			print(data)
			await reader.seek(10,0)
			data = await reader.read()
			print(data)
			await reader.seek(10,0)
			data = await reader.read(5)
			print(data)
			await reader.seek(-10,2)
			data = await reader.read(5)
			print(data)
			"""
	
if __name__ == '__main__':
	logging.basicConfig(level=logging.DEBUG) 
	connection_string = 'TEST/victim/ntlm/password:Passw0rd!1@10.10.10.2'	
	#connection_string = 'TEST/victim/ntlm/password:Passw0rd!1@win2019ad.test.corp/10.10.10.2'
	filename = '\\\\10.10.10.2\\Users\\Administrator\\Desktop\\smb_test\\testfile1.txt'
	#proxy = 'socks5://127.0.0.1:32903'
	proxy = 'multiplexor://127.0.0.1:9999/2e454cee-b046-466c-a2b4-d33149835218'
	
	
	asyncio.run(filereader_test(connection_string, filename, proxy))
	
	
	'TODO: TEST NT hash with ntlm!'