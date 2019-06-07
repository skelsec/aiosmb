import asyncio

import enum
import os

from aiosmb.commons.smbcredential import SMBCredential
from aiosmb.commons.smbtarget import SMBTarget
from aiosmb.smbconnection import SMBConnection
from aiosmb.filereader import SMBFileReader
from aiosmb.commons.authenticator_builder import AuthenticatorBuilder
from aiosmb.dcerpc.v5.transport.smbtransport import SMBTransport
from aiosmb.dcerpc.v5.interfaces.samrmgr import SMBSAMR
		
	

		

async def filereader_test(connection_string, filename):
	target = SMBTarget.from_connection_string(connection_string)
	credential = SMBCredential.from_connection_string(connection_string)
	
	spneg = AuthenticatorBuilder.to_spnego_cred(credential, target)
	
	async with SMBConnection(spneg, target) as connection: 
		await connection.login()
		
		samr = SMBSAMR(connection)
		await samr.connect()
		async for domain in samr.list_domains():
			print('domain: %s' % domain)
		domain_sid = await samr.get_domain_sid('TEST')
		print(str(domain_sid))
		domain_handle = await samr.open_domain(domain_sid)
		print(domain_handle)
		async for username in samr.list_domain_users(domain_handle):
			print(username)
			
		async for groupname in samr.list_domain_groups(domain_handle):
			print(groupname)
			
			
		async for sid, username in  samr.enumerate_users(domain_handle):
			print(username, sid)
			
			
		user_handle = await samr.open_user(domain_handle, 1106)
		input(user_handle)
		async for sid in samr.get_user_group_memberships(user_handle):
			print(sid)
		
		#polling local goup users
		local_domain_sid = await samr.get_domain_sid('Builtin')
		domain_handle = await samr.open_domain(local_domain_sid)
		alias_handle = await samr.open_alias(domain_handle, 544)
		async for sid in samr.list_alias_members(alias_handle):
			print(sid)
		
	
if __name__ == '__main__':
	connection_string = 'TEST/victim/ntlm/password:Passw0rd!1@10.10.10.2'	
	#connection_string = 'TEST/Administrator/ntlm/password:QLFbT8zkiFGlJuf0B3Qq@win2019ad.test.corp/10.10.10.2'
	#connection_string = 'TEST/Administrator/sspi-ntlm/password:QLFbT8zkiFGlJuf0B3Qq@win2019ad.test.corp/10.10.10.2'
	#connection_string = 'TEST/Administrator/kerberos/password:QLFbT8zkiFGlJuf0B3Qq@win2019ad.test.corp/10.10.10.2'
	#connection_string = 'TEST.corp/Administrator/sspi-kerberos@win2019ad.test.corp/10.10.10.2'
	filename = '\\\\10.10.10.2\\Users\\Administrator\\Desktop\\smb_test\\testfile1.txt'
	
	
	asyncio.run(filereader_test(connection_string, filename))
	
	
	'TODO: TEST NT hash with ntlm!'