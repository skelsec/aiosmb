
import asyncio
import traceback
import logging

from aiosmb import logger
from aiosmb._version import __banner__
from aiosmb.commons.connection.factory import SMBConnectionFactory
from aiosmb.dcerpc.v5.connection import DCERPC5Connection
from aiosmb.dcerpc.v5.common.connection.authentication import DCERPCAuth
from aiosmb.dcerpc.v5.interfaces.endpointmgr import EPM
from aiosmb.dcerpc.v5.interfaces.servicemanager import REMSVCRPC, ServiceStatus

async def amain(url):
	try:
		print('[+] Parsing connection parameters...')
		su = SMBConnectionFactory.from_url(url)
		ip = su.get_target().get_hostname_or_ip()
		
		print('[+] Connecting to EPM...')
		target, err = await EPM.create_target(ip, REMSVCRPC().service_uuid, dc_ip = su.get_target().dc_ip, domain = su.get_target().domain)
		if err is not None:
			raise err
		
		print('[+] Connecting to Remote Service Manager service...')
		auth = DCERPCAuth.from_smb_gssapi(su.get_credential())
		connection = DCERPC5Connection(auth, target)
		rpc, err = await REMSVCRPC.from_rpcconnection(connection, perform_dummy=True)
		if err is not None:
			raise err
		logger.debug('Service DCE Connected!')

		# now you can use service manager via DCE here

		async for service, err in rpc.list():
			if err is not None:
				raise err
			print(service)
		
		
		print('[+] Finished!')
		return True, None
	except Exception as e:
		traceback.print_exc()
		return False, e


def main():
	import argparse

	parser = argparse.ArgumentParser(description='Remore Registry Service client via DCE/RPC')
	parser.add_argument('-v', '--verbose', action='count', default=0)
	parser.add_argument('smb_url', help = 'Connection string that describes the authentication and target. Example: smb+ntlm-password://TEST\\Administrator:password@10.10.10.2')
	
	args = parser.parse_args()
	print(__banner__)

	if args.verbose >=1:
		logger.setLevel(logging.DEBUG)

	asyncio.run(
		amain(
			args.smb_url,
		)
	)

if __name__ == '__main__':
	main()