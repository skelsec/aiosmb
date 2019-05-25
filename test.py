import asyncio

from aiosmb.commons.smbcredential import SMBCredential
from aiosmb.commons.smbtarget import SMBTarget
from aiosmb.smbconnection import SMBConnection
from aiosmb.filereader import SMBFileReader
from aiosmb.commons.authenticator_builder import AuthenticatorBuilder

async def filereader_test(connection_string, filename):
	target = SMBTarget.from_connection_string(connection_string)
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
	#connection_string = 'TEST/victim/ntlm/password:Passw0rd!1@10.10.10.2'	
	connection_string = 'TEST/victim/ntlm/password:Passw0rd!1@win2019ad.test.corp/10.10.10.2'
	filename = '\\\\10.10.10.2\\Users\\Administrator\\Desktop\\smb_test\\testfile1.txt'
	
	
	asyncio.run(filereader_test(connection_string, filename))
	
	
	'TODO: TEST NT hash with ntlm!'