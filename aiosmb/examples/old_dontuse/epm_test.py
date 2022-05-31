import asyncio
import logging

from aiosmb.commons.connection.url import SMBConnectionURL
from aiosmb.connection import SMBConnection
from aiosmb.commons.connection.authbuilder import AuthenticatorBuilder
from aiosmb.dcerpc.v5.interfaces.endpointmgr import EPM
from aiosmb.dcerpc.v5 import drsuapi

from aiosmb.commons.utils.decorators import red, rr

async def filereader_test(connection_string, filename, proxy = None):
	cu = SMBConnectionURL(connection_string)
	smb_connection = cu.get_connection()
	

	epm = EPM(smb_connection, protocol = 'ncacn_ip_tcp')
	_, err = await epm.connect()
	if err is not None:
		raise err
	data, exc = await epm.map(drsuapi.MSRPC_UUID_DRSUAPI)
	#data, exc = await epm.lookup()
	if exc is not None:
		raise exc
	
	print(data)
	
if __name__ == '__main__':
	logging.basicConfig(level=logging.DEBUG) 
	filename = '\\\\10.10.10.2\\Users\\Administrator\\Desktop\\smb_test\\testfile1.txt'
	#proxy = 'socks5://127.0.0.1:32903'
	#proxy = 'multiplexor://127.0.0.1:9999/2e454cee-b046-466c-a2b4-d33149835218'

	connection_url = 'smb+ntlm-password://TEST\\victim:Passw0rd!1@10.10.10.2/'
	#connection_url = 'smb+multiplexor-kerberos://WIN2019AD/?proxytype=multiplexor&proxyhost=127.0.0.1&proxyport=9999&proxytimeout=10&authhost=127.0.0.1&authport=9999&proxyagentid=1ec511e0-1c8a-4315-9cc4-129267287527&authagentid=1ec511e0-1c8a-4315-9cc4-129267287527'

	
	asyncio.run(filereader_test(connection_url, filename))
	
	
	'TODO: TEST NT hash with ntlm!'