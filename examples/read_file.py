#
#
# Simple example of reading a file and printoint out its contects to stdout
#
import asyncio

from aiosmb.commons.smbcredential import SMBCredential
from aiosmb.commons.smbtarget import SMBTarget
from aiosmb.smbconnection import SMBConnection
from aiosmb.filereader import SMBFileReader
from aiosmb.commons.authenticator_builder import AuthenticatorBuilder

async def read_file(connection_string, filename):
	target = SMBTarget.from_connection_string(connection_string)
	credential = SMBCredential.from_connection_string(connection_string)
	
	spneg = AuthenticatorBuilder.to_spnego_cred(credential, target)
	
	async with SMBConnection(spneg, target) as connection: 
		await connection.login()
		
		async with SMBFileReader(connection) as reader:
			await reader.open(filename)
			data = await reader.read()
			print(data)

	
if __name__ == '__main__':
	#connection_string = 'TEST/victim/ntlm/password:Passw0rd!1@10.10.10.2'	
	#connection_string = 'TEST/victim/ntlm/nt:f8963568a1ec62a3161d9d6449baba93@10.10.10.2'
	#connection_string = 'TEST/victim/ntlm/password:Passw0rd!1@win2019ad.test.corp/10.10.10.2'
	#connection_string = 'TEST/victim/kerberos/password:Passw0rd!1@win2019ad.test.corp/10.10.10.2'
	#connection_string = 'TEST/victim/sspi-kerberos/password:Passw0rd!1@win2019ad.test.corp/10.10.10.2'
	#connection_string = 'TEST/victim/sspi-ntlm/password:Passw0rd!1@win2019ad.test.corp/10.10.10.2'
	#filename = '\\\\10.10.10.2\\Users\\Administrator\\Desktop\\smb_test\\testfile1.txt'
	
	import argparse
	
	parser = argparse.ArgumentParser(description='Sample script to read file over an SMB connection with aiosmb')
	parser.add_argument('-v', '--verbose', action='count', default=0)
	parser.add_argument('connection_string', help = 'Connection string that describes the authentication and target')
	parser.add_argument('file_path', help = 'file to read, in the following format: \\\\<server\\share\\....\\file.ext>')
	
	args = parser.parse_args()
	
	asyncio.run(read_file(args.connection_string, args.file_path))
	
	
	#'TODO: TEST NT hash with ntlm!'