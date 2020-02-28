import asyncio
import logging
import json

import aiosmb
from aiosmb.commons.connection.credential import SMBCredential
from aiosmb.commons.connection.target import SMBTarget
from aiosmb.commons.connection.authbuilder import AuthenticatorBuilder
from aiosmb.connection import SMBConnection

from aiosmb.dcerpc.v5.transport.smbtransport import SMBTransport
from aiosmb.dcerpc.v5.interfaces.samrmgr import SMBSAMR
from aiosmb.dcerpc.v5 import samr

class SMBDomain:
	def __init__(self, domain_name, samr = None, connection = None):
		self.domain_name = domain_name
		self.connection = connection
		self.domain_access_level = None
		self.samr = samr
		self.domain_sid = None
		self.domain_handle = None
		
		if samr is None and connection is None:
			raise Exception('Either SAMR or CONNECTION must be provided!')
			
	async def __aenter__(self):
		return self
		
	async def __aexit__(self, exc_type, exc, traceback):
		pass
	
	async def open(self, access_level = samr.MAXIMUM_ALLOWED):
		self.domain_access_level = access_level
		if self.samr is None:
			self.samr = SMBSAMR(self.connection)
			logging.debug('Connecting to SAMR')
			try:
				await self.samr.connect()
			except Exception as e:
				logging.exception('Failed to connect to SAMR')
				raise e
				
		self.domain_sid = await self.samr.get_domain_sid(self.domain_name)
		self.domain_handle = await self.samr.open_domain(self.domain_sid, access_level = self.domain_access_level)
		#print(self.domain_sid)
		
	async def get_info(self):
		for i in [
				samr.DOMAIN_INFORMATION_CLASS.DomainPasswordInformation,
				samr.DOMAIN_INFORMATION_CLASS.DomainGeneralInformation2,
			]:
			info = await self.samr.get_info(self.domain_handle, i)
			info.dump()	
		
		return info
		
	async def list_users(self):
		async for user_name, user_sid in self.samr.enumerate_users(self.domain_handle):
			yield (user_name, user_sid)
			
	async def open_user(self, user_sid, access_level = samr.MAXIMUM_ALLOWED):
		user_rid = user_sid.replace(self.domain_sid, '')[1:]
		user_handle = await self.samr.open_user(self.domain_handle, int(user_rid), access_level = access_level)
		return user_handle
		
	async def get_user_group_memberships(self, user_handle):
		async for group_sid in self.samr.get_user_group_memberships(user_handle):
			yield group_sid
			
	async def get_user_info(self, user_handle):
		info = await self.samr.get_user_info(user_handle, samr.USER_INFORMATION_CLASS.UserParametersInformation)
		info.dump()
		return info
		
	async def list_groups(self):
		async for name, sid in self.samr.list_domain_groups(self.domain_handle):
			yield name, sid
			
	async def get_security_info(self, handle):
		info = await self.samr.get_security_info(handle)
		info.dump()
		return info
	
		
	
	
	
	
async def domain_test(connection_string, domain_name, out_file = None, json_out = False):
	target = SMBTarget.from_connection_string(connection_string)
	credential = SMBCredential.from_connection_string(connection_string)
	spneg = AuthenticatorBuilder.to_spnego_cred(credential, target)
	
	async with SMBConnection(spneg, target) as connection: 
		await connection.login()
		
		async with SMBDomain(domain_name, connection=connection) as domain:
			logging.debug('Connecting to SAMR')
			try:
				await domain.open(access_level = samr.DOMAIN_ALL_ACCESS)
			except Exception as e:
				logging.exception('Failed to create domain object')
				
			info = await domain.get_info()
			
			async for user_name, user_sid in domain.list_users():
				print(user_name, user_sid)
				try:
					user_handle = await domain.open_user(user_sid, access_level = samr.USER_ALL_ACCESS)
					#x = await domain.get_security_info(user_handle)
					user_info = await domain.get_user_info(user_handle)
					
					#async for group_sid in domain.get_user_group_memberships(user_handle):
					#	print(group_sid)
				except Exception as e:
					print(e)
					continue
					
			#async for name, sid in domain.list_groups():
			#	print(name, sid)

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
	
	asyncio.run(domain_test(args.connection_string, 'TEST', out_file = args.out_file, json_out = args.json))
	