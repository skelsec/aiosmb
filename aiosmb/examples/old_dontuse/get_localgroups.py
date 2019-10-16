import asyncio
import logging
import json

import aiosmb
from aiosmb.commons.smbcredential import SMBCredential
from aiosmb.commons.smbtarget import SMBTarget
from aiosmb.smbconnection import SMBConnection
from aiosmb.commons.authenticator_builder import AuthenticatorBuilder
from aiosmb.dcerpc.v5.transport.smbtransport import SMBTransport
from aiosmb.dcerpc.v5.interfaces.samrmgr import SMBSAMR


async def list_localgroup_members(connection_string, groupname = 'Administrators', out_file = None, json_out = False):
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
				logging.exception('Failed to connect to SAMR')
				
			#list domain
			found = False
			async for domain in samr.list_domains():
				#print(domain)
				if domain == 'Builtin':
					found = True
					logging.info('[+] Found Builtin domain')
			
			if found == False:
				raise Exception('[-] Could not find Builtin domain. Fail.')
			#open domain
			domain_sid = await samr.get_domain_sid('Builtin')
			domain_handle = await samr.open_domain(domain_sid)
			
			#list aliases
			found = False
			target_rid = None
			async for name, rid in samr.list_aliases(domain_handle):
				#print(name, rid)
				if name == groupname:
					target_rid = rid
					found = True
					logging.info('[+] Found %s group!' % name)
					break
					
			if found == False:
				raise Exception('[-] %s group not found! Fail.' % name)
			
			#open alias
			alias_handle = await samr.open_alias(domain_handle, target_rid)
			#list alias memebers
			async for sid in samr.list_alias_members(alias_handle):
				print(sid)
			
			

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
	
	asyncio.run(list_localgroup_members(args.connection_string, out_file = args.out_file, json_out = args.json))
	