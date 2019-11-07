
import asyncio
import ntpath
import os

from aiosmb import logger
from aiosmb.commons.interfaces.share import SMBShare
from aiosmb.commons.interfaces.session import SMBUserSession
from aiosmb.commons.interfaces.file import SMBFile
from aiosmb.dcerpc.v5.interfaces.srvsmgr import SMBSRVS
from aiosmb.dcerpc.v5.interfaces.samrmgr import SMBSAMR
from aiosmb.dcerpc.v5.interfaces.lsatmgr import LSAD
from aiosmb.dcerpc.v5.interfaces.drsuapimgr import SMBDRSUAPI
from aiosmb.dcerpc.v5.interfaces.servicemanager import SMBRemoteServieManager
from aiosmb.dcerpc.v5.interfaces.remoteregistry import RRP
from aiosmb.commons.utils.decorators import red, rr, red_gen, rr_gen


def req_srvs_gen(funct):
	async def wrapper(*args, **kwargs):
		this = args[0]
		try:
			if this.srvs is None:
				await rr(this.connect_rpc('SRVS'))
			async for x in  funct(*args, **kwargs):
				if x[-1] is not None:
					raise x[-1]
				yield x
		except Exception as e:
			raise e
	return wrapper

def req_rrp(funct):
	async def wrapper(*args, **kwargs):
		this = args[0]
		try:
			if this.rrp is None:
				await rr(this.connect_rpc('RRP'))
			x = await funct(*args, **kwargs)
			return x
		except Exception as e:
			raise e
	return wrapper

def req_samr_gen(funct):
	async def wrapper(*args, **kwargs):
		this = args[0]
		try:
			if this.samr is None:
				await rr(this.connect_rpc('SAMR'))
			async for x in funct(*args, **kwargs):
				if x[-1] is not None:
					raise x[-1]
				yield x
		except Exception as e:
			raise e
	return wrapper

def req_lsad_gen(funct):
	async def wrapper(*args, **kwargs):
		this = args[0]
		try:
			if this.lsad is None:
				await rr(this.connect_rpc('LSAD'))
			async for x in  funct(*args, **kwargs):
				if x[-1] is not None:
					raise x[-1]
				yield x
		except Exception as e:
			raise e
	return wrapper

def req_servicemanager_gen(funct):
	async def wrapper(*args, **kwargs):
		this = args[0]
		try:
			if this.servicemanager is None:
				await rr(this.connect_servicemanager())
			async for x in funct(*args, **kwargs):
				if x[-1] is not None:
					raise x[-1]
				yield x
		except Exception as e:
			raise e
	return wrapper

def req_servicemanager(funct):
	async def wrapper(*args, **kwargs):
		this = args[0]
		try:
			if this.servicemanager is None:
				await rr(this.connect_servicemanager())
			x = await funct(*args, **kwargs)
			return x
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
		self.rrp = None

		self.filesystem = None
		self.servicemanager = None

	@red
	async def connect_rpc(self, service_name):
		if service_name.upper() == 'SRVS':
			self.srvs = SMBSRVS(self.connection)
			await rr(self.srvs.connect())
		elif service_name.upper() == 'SAMR':
			self.samr = SMBSAMR(self.connection)
			await rr(self.samr.connect())
		elif service_name.upper() == 'LSAD':
			self.lsad = LSAD(self.connection)
			await rr(self.lsad.connect())
		elif service_name.upper() == 'RRP':
			self.rrp = RRP(self.connection)
			await rr(self.rrp.connect())
		else:
			raise Exception('Unknown service name : %s' % service_name)
		return True, None
	
	@red
	async def connect_servicemanager(self):
		self.servicemanager = SMBRemoteServieManager(self.connection)
		await self.servicemanager.connect()
		return True, None

	@req_srvs_gen
	async def list_shares(self):
		async for name, share_type, remark, _ in rr_gen(self.srvs.list_shares()):
			share = SMBShare(
				name = name, 
				stype = share_type, 
				remark = remark, 
				fullpath = '\\\\%s\\%s' % (self.connection.target.get_hostname_or_ip(), name)
			)
			self.shares.append(share)
			yield share, None

	@req_srvs_gen
	async def list_sessions(self, level = 1):
		async for username, ip_addr, _ in rr_gen(self.srvs.list_sessions(level = level)):
			sess = SMBUserSession(username = username, ip_addr = ip_addr.replace('\\','').strip())
			self.sessions.append(sess)
			yield sess, None

	@req_samr_gen
	async def list_domains(self):
		async for domain, _ in rr_gen(self.samr.list_domains()):
			self.domains.append(domain)
			yield domain, None
	
	@req_samr_gen
	async def list_localgroups(self):
		async for name, sid, _ in rr_gen(self.list_groups('Builtin')):
			yield name, sid, None

	@req_samr_gen
	async def list_groups(self, domain_name, ret_sid = True):
		"""
		Lists all groups in a given domain.
		domain_name: string
		"""
		domain_sid, _ = await rr(self.samr.get_domain_sid(domain_name))
		domain_handle, _ = await rr(self.samr.open_domain(domain_sid))
		#target_group_rids = {}
		async for name, rid, _ in rr_gen(self.samr.list_aliases(domain_handle)):
			sid = '%s-%s' % (domain_sid, rid)
			yield name, sid, None

	@req_samr_gen
	@req_lsad_gen
	async def list_group_members(self, domain_name, group_name):
		policy_handle, _ = await rr(self.lsad.open_policy2())
		domain_sid, _ = await rr(self.samr.get_domain_sid(domain_name))
		domain_handle, _ = await rr(self.samr.open_domain(domain_sid))
		target_group_rid = None
		async for name, rid, _ in rr_gen(self.samr.list_aliases(domain_handle)):
			if name == group_name:
				target_group_rid = rid
				break

		if target_group_rid is None:
			raise Exception('No group found with name "%s"' % group_name)
		
		alias_handle, _ = await rr(self.samr.open_alias(domain_handle, target_group_rid))
		async for sid, _ in rr_gen(self.samr.list_alias_members(alias_handle)):
			async for domain_name, user_name, _ in rr_gen(self.lsad.lookup_sids(policy_handle, [sid])):
				yield domain_name, user_name, sid, None


	async def list_directory(self, directory):
		await directory.list(self.connection)
		for entry in directory.get_console_output():
			yield entry

	async def put_file(self, local_path, remote_path):
		"""
		remote_path must be a full UNC path with the file name included!

		"""
		smbfile = SMBFile.from_remotepath(self.connection, remote_path)
		await smbfile.open(self.connection, 'w')
		with open(local_path, 'rb') as f:
			await smbfile.write_buffer(f)
		await smbfile.close()
		return True

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

	async def get_file_data(self, file_obj):
		await file_obj.open(self.connection, 'r')
		async for data in file_obj.read_chunked():
			yield data

	async def del_file(self, file_path):
		await SMBFile.delete(self.connection, file_path)

	async def create_subdirectory(self, directory_name, parent_directory_obj):
		await parent_directory_obj.create_subdir(directory_name, self.connection)
		

	@req_servicemanager_gen
	async def list_services(self):
		async for service, _ in rr_gen(self.servicemanager.list()):
			yield service, None

	@req_servicemanager
	async def enable_service(self, service_name):
		res, exc = await rr(self.servicemanager.enable_service(service_name))
		return res, exc

	@red_gen
	@req_samr_gen
	async def dcsync(self, target_domain = None, target_users = []):		
		
		if target_domain is None:
			logger.debug('No domain defined, fetching it from SAMR')
					
							
			logger.debug('Fetching domains...')
			async for domain, _ in rr_gen(self.samr.list_domains()):
				if domain == 'Builtin':
					continue
				if target_domain is None: #using th first available
					target_domain = domain
					logger.debug('Domain available: %s' % domain)
		
		async with SMBDRSUAPI(self.connection, target_domain) as drsuapi:
			try:
				await rr(drsuapi.connect())
				await rr(drsuapi.open())
			except Exception as e:
				logger.exception('Failed to connect to DRSUAPI!')
				raise e

			logger.debug('Using domain: %s' % target_domain)
			if len(target_users) > 0:
				for username in target_users:
					secrets, _ = await drsuapi.get_user_secrets(username)
					yield secrets
							
			else:
				domain_sid, _ = await self.samr.get_domain_sid(target_domain)
				domain_handle, _ = await self.samr.open_domain(domain_sid)
				async for username, user_sid, _ in rr_gen(self.samr.list_domain_users(domain_handle)):
					secrets = await drsuapi.get_user_secrets(username)
					yield secrets

	
	@req_rrp
	async def save_registry_hive(self, hive_name, remote_path):
		#SAM C:\aaaa\sam.reg
		res, _ = await rr(self.rrp.save_hive(hive_name, remote_path))
		return True, None

	@req_servicemanager
	async def create_service(self, service_name, command, display_name = None):
		"""
		Creates a service and starts it.
		Does not create files! there is a separate command for that!
		"""
		if display_name is None:
			display_name = service_name
		res, _ = await rr(self.servicemanager.create_service(service_name, display_name, command))
		return True, None


	@req_servicemanager
	async def deploy_service(self, path_to_executable, remote_path = None, service_name = None):
		"""

		remote path must be UNC
		"""
		if service_name is None:
			service_name = os.urandom(4).hex()
		if remote_path is None:
			raise NotImplementedError()

		filename = ntpath.basename(path_to_executable)
		remote_file_path = remote_path + filename
		remote_file = SMBFile.from_uncpath(remote_file_path)
		await self.put_file(path_to_executable, remote_file)
		
		command = remote_file_path

		await self.create_service(service_name, command)

		return True, None

	async def stop_service(self):
		pass
	
	async def list_mountpoints(self):
		pass

