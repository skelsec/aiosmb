import asyncio

import enum
import os

from aiosmb.commons.smbcredential import SMBCredential
from aiosmb.commons.smbtarget import SMBTarget
from aiosmb.smbconnection import SMBConnection
from aiosmb.filereader import SMBFileReader
from aiosmb.commons.authenticator_builder import AuthenticatorBuilder
from aiosmb.dcerpc.v5.transport.smbtransport import SMBTransport
from aiosmb.dcerpc.v5.interfaces.srvsmgr import SMBSRVS
		
	

		

async def filereader_test(connection_string, filename):
	target = SMBTarget.from_connection_string(connection_string)
	credential = SMBCredential.from_connection_string(connection_string)
	
	spneg = AuthenticatorBuilder.to_spnego_cred(credential, target)
	
	async with SMBConnection(spneg, target) as connection:
		
		try:
			await connection.login()
		except Exception as e:
			print(str(e))
			raise e
		print(connection)
		srvs = SMBSRVS(connection)
		await srvs.connect()
		
		async for name, share_type, remark in srvs.list_shares():
			print(name, share_type, remark)
		#async for user, ip in srvs.list_sessions():
		#	print(user, ip)
		
		
	
if __name__ == '__main__':
	#connection_string = 'TEST/victim/ntlm/password:Passw0rd!1@10.10.10.2'	
	connection_string = 'TEST/Administrator/ntlm/password:QLFbT8zkiFGlJuf0B3Qq@win2019ad.test.corp/10.10.10.2'
	#connection_string = 'TEST/Administrator/sspi-ntlm/password:QLFbT8zkiFGlJuf0B3Qq@win2019ad.test.corp/10.10.10.2'
	#connection_string = 'TEST/Administrator/kerberos/password:QLFbT8zkiFGlJuf0B3Qq@win2019ad.test.corp/10.10.10.2'
	#connection_string = 'TEST.corp/Administrator/sspi-kerberos@win2019ad.test.corp/10.10.10.2'
	filename = '\\\\10.10.10.2\\Users\\Administrator\\Desktop\\smb_test\\testfile1.txt'
	
	
	asyncio.run(filereader_test(connection_string, filename))
	
	
	'TODO: TEST NT hash with ntlm!'