import asyncio
import logging

from aiosmb.commons.connection.credential import SMBCredential
from aiosmb.commons.connection.target import SMBTarget
from aiosmb.commons.connection.targetproxy import SMBTargetProxy
from aiosmb.commons.connection.url import SMBConnectionURL
from aiosmb.smbconnection import SMBConnection
from aiosmb.filereader import SMBFileReader
from aiosmb.commons.connection.authbuilder import AuthenticatorBuilder

async def filereader_test(connection_string, filename, proxy = None):
	#target = SMBTarget.from_connection_string(connection_string)
	#if proxy is not None:
	#	target.proxy = SMBTargetProxy.from_connection_string(proxy)
	#	print(str(target))
	#
	#credential = SMBCredential.from_connection_string(connection_string)
	cu = SMBConnectionURL(connection_string)
	credential = cu.get_credential()
	target = cu.get_target()

	print(credential)
	print(target)
	input()

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
	#connection_string = 'TEST/victim/ntlm/password:Passw0rd!1@10.10.10.2'	
	#connection_string = 'TEST/victim/ntlm/password:Passw0rd!1@win2019ad.test.corp/10.10.10.2'
	filename = '\\\\10.10.10.2\\Users\\Administrator\\Desktop\\smb_test\\testfile1.txt'
	#proxy = 'socks5://127.0.0.1:32903'
	#proxy = 'multiplexor://127.0.0.1:9999/2e454cee-b046-466c-a2b4-d33149835218'

	#connection_url = 'smb+ntlm-password://TEST\\victim:Passw0rd!1@10.10.10.2/?proxytype=multiplexor&proxyhost=127.0.0.1&proxyport=9999&proxytimeout=10&authhost=127.0.0.1&authport=9999&proxyagentid=b326745f-2105-4a06-903b-c3ed39f44ce3&authagentid=b326745f-2105-4a06-903b-c3ed39f44ce3'
	connection_url = 'smb+multiplexor-kerberos://WIN2019AD/?proxytype=multiplexor&proxyhost=127.0.0.1&proxyport=9999&proxytimeout=10&authhost=127.0.0.1&authport=9999&proxyagentid=1ec511e0-1c8a-4315-9cc4-129267287527&authagentid=1ec511e0-1c8a-4315-9cc4-129267287527'

	
	asyncio.run(filereader_test(connection_url, filename))
	
	
	'TODO: TEST NT hash with ntlm!'