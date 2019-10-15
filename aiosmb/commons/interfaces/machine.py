
from aiosmb import logger
import asyncio
from aiosmb.filesystem import SMBFileSystem
from aiosmb.commons.interfaces.share import SMBShare
from aiosmb.commons.interfaces.session import SMBUserSession
from aiosmb.dcerpc.v5.interfaces.srvsmgr import SMBSRVS
from aiosmb.dcerpc.v5.interfaces.samrmgr import SMBSAMR
from aiosmb.dcerpc.v5.interfaces.lsatmgr import LSAD
from aiosmb.dcerpc.v5.interfaces.drsuapimgr import SMBDRSUAPI
from aiosmb.dcerpc.v5.interfaces.servicemanager import SMBRemoteServieManager
from aiosmb.filereader import SMBFileReader


def req_srvs_gen(funct):
	async def wrapper(*args, **kwargs):
		this = args[0]
		try:
			if this.srvs is None:
				await this.connect_rpc('SRVS')
			async for x in  funct(*args, **kwargs):
				yield x
		except Exception as e:
			raise e
	return wrapper

def req_samr_gen(funct):
	async def wrapper(*args, **kwargs):
		this = args[0]
		try:
			if this.srvs is None:
				await this.connect_rpc('SAMR')
			async for x in  funct(*args, **kwargs):
				yield x
		except Exception as e:
			raise e
	return wrapper

def req_lsad_gen(funct):
	async def wrapper(*args, **kwargs):
		this = args[0]
		try:
			if this.srvs is None:
				await this.connect_rpc('LSAD')
			async for x in  funct(*args, **kwargs):
				yield x
		except Exception as e:
			raise e
	return wrapper

def req_filesystem_gen(funct):
	async def wrapper(*args, **kwargs):
		this = args[0]
		try:
			if this.filesystem is None:
				await this.connect_filesystem()
			async for x in  funct(*args, **kwargs):
				yield x
		except Exception as e:
			raise e
	return wrapper

def req_filesystem(funct):
	async def wrapper(*args, **kwargs):
		this = args[0]
		try:
			if this.filesystem is None:
				await this.connect_filesystem()
			x = await funct(*args, **kwargs)
			return x
		except Exception as e:
			raise e
	return wrapper

def req_servicemanager_gen(funct):
	async def wrapper(*args, **kwargs):
		this = args[0]
		try:
			if this.filesystem is None:
				await this.connect_servicemanager()
			async for x in funct(*args, **kwargs):
				yield x
		except Exception as e:
			raise e
	return wrapper

class SMBMachine:
	def __init__(self, connection):
		self.connection = connection
		self.services = []
		self.shares = []
		self.localgroups = []
		self.sessions = []
		self.domains = []

		self.srvs = None
		self.samr = None
		self.lsad = None

		self.filesystem = None
		self.servicemanager = None

	async def connect_rpc(self, service_name):
		if service_name.upper() == 'SRVS':
			self.srvs = SMBSRVS(self.connection)
			await self.srvs.connect()
		elif service_name.upper() == 'SAMR':
			self.samr = SMBSAMR(self.connection)
			await self.samr.connect()
		elif service_name.upper() == 'LSAD':
			self.lsad = LSAD(self.connection)
			await self.lsad.connect()
		else:
			raise Exception('Unknown service name : %s' % service_name)

	async def connect_filesystem(self):
		self.filesystem = SMBFileSystem(self.connection)
	
	async def connect_servicemanager(self):
		self.servicemanager = SMBRemoteServieManager(self.connection)
		await self.servicemanager.connect()

	@req_srvs_gen
	async def list_shares(self):
		async for name, share_type, remark in self.srvs.list_shares():
			share = SMBShare(
				name = name, 
				stype = share_type, 
				remark = remark, 
				fullpath = '\\\\%s\\%s' % (self.connection.target.get_hostname_or_ip(), name)
			)
			self.shares.append(share)
			yield share

	@req_srvs_gen
	async def list_sessions(self, level = 1):
		async for username, ip_addr in self.srvs.list_sessions(level = level):
			sess = SMBUserSession(username = username, ip_addr = ip_addr.replace('\\','').strip())
			self.sessions.append(sess)
			yield sess

	@req_samr_gen
	async def list_domains(self):
		async for domain in self.samr.list_domains():
			self.domains.append(domain)
			yield domain
	
	@req_samr_gen
	async def list_localgroups(self):
		async for group in self.list_groups('Builtin'):
			yield group

	@req_samr_gen
	async def list_groups(self, domain_name, ret_sid = True):
		"""
		Lists all groups in a given domain.
		domain_name: string
		"""
		domain_sid = await self.samr.get_domain_sid(domain_name)
		domain_handle = await self.samr.open_domain(domain_sid)
		#target_group_rids = {}
		async for name, rid in self.samr.list_aliases(domain_handle):
			sid = '%s-%s' % (domain_sid, rid)
			yield name, sid

	@req_samr_gen
	@req_lsad_gen
	async def list_group_members(self, domain_name, group_name):
		policy_handle = await self.lsad.open_policy2()
		domain_sid = await self.samr.get_domain_sid(domain_name)
		domain_handle = await self.samr.open_domain(domain_sid)
		target_group_rid = None
		async for name, rid in self.samr.list_aliases(domain_handle):
			if name == group_name:
				target_group_rid = rid
				break
		
		alias_handle = await self.samr.open_alias(domain_handle, target_group_rid)
		async for sid in self.samr.list_alias_members(alias_handle):
			async for domain_name, user_name in self.lsad.lookup_sids(policy_handle, [sid]):
				yield (domain_name, user_name, sid)


	async def list_directory(self, directory):
		await directory.list(self.connection)
		for entry in directory.get_console_output():
			yield entry

	async def put_file_raw(self, local_path, remote_path):
		"""
		remote_path must be a full UNC path with the file name included!

		"""
		with open(local_path, 'rb') as f:
			async with SMBFileReader(self.connection) as writer:
				await writer.open(remote_path, 'w')
				while True:
					await asyncio.sleep(0)
					data = f.read(1024)
					if not data:
						break
					await writer.write(data)

	async def get_file(self, out_path, file_obj):
		with open(out_path, 'wb') as f:
			try:
				await file_obj.open(self.connection, 'r')
				while True:
					data = await file_obj.read(1024)
					if not data:
						break
					f.write(data)
			finally:
				await file_obj.close()

	async def create_subdirectory(self, directory_name, parent_directory_obj):
		await parent_directory_obj.create_subdir(directory_name, self.connection)
		

	@req_servicemanager_gen
	async def list_services(self):
		async for service in self.servicemanager.list():
			yield service


	@req_samr_gen
	async def dcsync(self, target_domain = None, target_users = []):		
		
		if target_domain is None:
			logger.debug('No domain defined, fetching it from SAMR')
					
							
			logger.debug('Fetching domains...')
			async for domain in self.samr.list_domains():
				if domain == 'Builtin':
					continue
				if target_domain is None: #using th first available
					target_domain = domain
					logger.debug('Domain available: %s' % domain)
		
		async with SMBDRSUAPI(self.connection, target_domain) as drsuapi:
			try:
				await drsuapi.connect()
				await drsuapi.open()
			except Exception as e:
				logger.exception('Failed to connect to DRSUAPI!')
				raise e

			logger.debug('Using domain: %s' % target_domain)
			if len(target_users) > 0:
				for username in target_users:
					secrets = await drsuapi.get_user_secrets(username)
					yield secrets
							
			else:
				domain_sid = await self.samr.get_domain_sid(target_domain)
				domain_handle = await self.samr.open_domain(domain_sid)
				async for username, user_sid in self.samr.list_domain_users(domain_handle):
					secrets = await drsuapi.get_user_secrets(username)
					yield secrets

	#placeholder for later implementations...
	async def save_registry(self, hive_name):
		pass
	async def stop_service(self):
		pass
	async def deploy_service(self):
		pass
	async def list_mountpoints(self):
		pass

