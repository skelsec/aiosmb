import asyncio
import logging
import json

import aiosmb
from aiosmb.commons.smbcredential import SMBCredential
from aiosmb.commons.smbtarget import SMBTarget
from aiosmb.smbconnection import SMBConnection
from aiosmb.commons.authenticator_builder import AuthenticatorBuilder
from aiosmb.dcerpc.v5.transport.smbtransport import SMBTransport
from aiosmb.dcerpc.v5.interfaces.srvsmgr import SMBSRVS


async def list_sessions(connection_string, filename = None, json_out = False):
	target = SMBTarget.from_connection_string(connection_string)
	credential = SMBCredential.from_connection_string(connection_string)
	spneg = AuthenticatorBuilder.to_spnego_cred(credential, target)
	
	async with SMBConnection(spneg, target) as connection: 
		await connection.login()
		
		async with SMBSRVS(connection) as srvs:
			logging.debug('Connecting to SAMR')
			try:
				await srvs.connect()
			except Exception as e:
				logging.exception('Failed to connect to SAMR')
			
			async for username, ip_addr in srvs.list_sessions():
				print(username, ip_addr)

	print('Done!')
if __name__ == '__main__':
	import argparse
	
	
	
	parser = argparse.ArgumentParser(description='List user sessions on a remote machine')
	parser.add_argument('-v', '--verbose', action='count', default=0, help='Increase verbosity, can be stacked')
	parser.add_argument('connection_string', help='connection string. Identifies the credential to be used and the target')
	parser.add_argument('-o', '--out-file', help='file to store the results in')
	parser.add_argument('--json', action='store_true', help='File output will be pritten in JSON format')
	args = parser.parse_args()	
	
	if args.verbose == 0:
		logging.basicConfig(level=logging.INFO)
		aiosmb.logger.setLevel(logging.WARNING)
		
	elif args.verbose == 1:
		logging.basicConfig(level=logging.DEBUG)
		aiosmb.logger.setLevel(logging.INFO)
		
	else:
		logging.basicConfig(level=1)
		aiosmb.logger.setLevel(logging.DEBUG)
	
	asyncio.run(list_sessions(args.connection_string, args.out_file, json_out = args.json))
	