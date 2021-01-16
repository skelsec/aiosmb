import asyncio
import traceback
import ntpath
import fnmatch

import shlex
import tqdm
from aiosmb.external.aiocmd.aiocmd import aiocmd
from aiosmb.examples.smbpathcompleter import SMBPathCompleter

from aiosmb import logger
from aiosmb._version import __banner__
from aiosmb.commons.connection.url import SMBConnectionURL
from aiosmb.commons.interfaces.machine import SMBMachine
from aiosmb.commons.interfaces.share import SMBShare
from aiosmb.commons.utils.decorators import rr, rr_gen, red, red_gen, ef_gen
from aiosmb.commons.exceptions import SMBException, SMBMachineException
from aiosmb.dcerpc.v5.rpcrt import DCERPCException

from asysocks import logger as sockslogger


def req_traceback(funct):
	async def wrapper(*args, **kwargs):
		this = args[0]
		try:
			x = await funct(*args, **kwargs)
			return x
		except Exception as e:
			traceback.print_exc()
			raise e
	return wrapper

class SMBClient(aiocmd.PromptToolkitCmd):
	def __init__(self, url = None, silent = False):
		aiocmd.PromptToolkitCmd.__init__(self, ignore_sigint=False) #Setting this to false, since True doesnt work on windows...
		self.conn_url = None
		if url is not None:
			self.conn_url = SMBConnectionURL(url)
		self.connection = None
		self.machine = None
		self.is_anon = False
		self.silent = silent

		self.shares = {} #name -> share
		self.__current_share = None
		self.__current_directory = None

	async def do_login(self, url = None):
		"""Connects to the remote machine"""
		try:
			if self.conn_url is None and url is None:
				print('No url was set, cant do logon')
			if url is not None:
				self.conn_url = SMBConnectionURL(url)

			cred = self.conn_url.get_credential()
			
			if cred.secret is None and cred.username is None and cred.domain is None:
				self.is_anon = True			
			
			self.connection  = self.conn_url.get_connection()
			
			logger.debug(self.conn_url.get_credential())
			logger.debug(self.conn_url.get_target())

			_, err = await self.connection.login()
			if err is not None:
				raise err
			self.machine = SMBMachine(self.connection)
			if self.silent is False:
				print('Login success')
			return True, None
		except Exception as e:
			traceback.print_exc()
			print('Login failed! Reason: %s' % str(e))
			return False, e

	async def do_logout(self):
		if self.machine is not None:
			await self.machine.close()
		self.machine = None

		if self.connection is not None:
			try:
				await self.connection.terminate()
			except Exception as e:
				logger.exception('connection.close')
		self.connection = None

	async def _on_close(self):
		await self.do_logout()

	async def do_shares(self, show = True):
		"""Lists available shares"""
		try:
			if self.machine is None:
				print('Not logged in! Use "login" first!')
				return False, Exception('Not logged in!')
			async for share, err in self.machine.list_shares():
				if err is not None:
					raise err
				self.shares[share.name] = share
				if show is True:
					print(share.name)
			return True, None
				
		except SMBException as e:
			logger.debug(traceback.format_exc())
			print(e.pprint())
			return None, e
		except SMBMachineException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
			return None, e
		except DCERPCException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
			return None, e
		except Exception as e:
			traceback.print_exc()
			return None, e
		

	async def do_sessions(self):
		"""Lists sessions of connected users"""
		try:
			async for sess, err in self.machine.list_sessions():
				if err is not None:
					raise err
				print("%s : %s" % (sess.username, sess.ip_addr))
		except SMBException as e:
			logger.debug(traceback.format_exc())
			print(e.pprint())
		except SMBMachineException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
		except DCERPCException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
		except Exception as e:
			traceback.print_exc()

	async def do_domains(self):
		"""Lists domain"""
		try:
			async for domain, err in self.machine.list_domains():
				if err is not None:
					raise err
				print(domain)
		except SMBException as e:
			logger.debug(traceback.format_exc())
			print(e.pprint())
		except SMBMachineException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
		except DCERPCException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
		except Exception as e:
			traceback.print_exc()

	async def do_localgroups(self):
		"""Lists local groups"""
		try:
			async for name, sid, err in self.machine.list_localgroups():
				if err is not None:
					raise err
				print("%s : %s" % (name, sid))
		except SMBException as e:
			logger.debug(traceback.format_exc())
			print(e.pprint())
		except SMBMachineException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
		except DCERPCException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
		except Exception as e:
			traceback.print_exc()
	
	async def do_domaingroups(self, domain_name):
		"""Lists groups in a domain"""
		try:
			async for name, sid, err in self.machine.list_groups(domain_name):
				if err is not None:
					raise err
				print("%s : %s" % (name, sid))
		except SMBException as e:
			logger.debug(traceback.format_exc())
			print(e.pprint())
		except SMBMachineException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
		except DCERPCException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
		except Exception as e:
			traceback.print_exc()
	
	async def do_groupmembers(self, domain_name, group_name):
		"""Lists members of an arbitrary group"""
		try:
			async for domain, username, sid, err in self.machine.list_group_members(domain_name, group_name):
				if err is not None:
					raise err
				print("%s\\%s : %s" % (domain, username, sid))
		except SMBException as e:
			logger.debug(traceback.format_exc())
			print(e.pprint())
		except SMBMachineException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
		except DCERPCException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
		except Exception as e:
			traceback.print_exc()

	async def do_localgroupmembers(self, group_name):
		"""Lists members of a local group"""
		try:
			async for domain, username, sid, err in self.machine.list_group_members('Builtin', group_name):
				if err is not None:
					raise err
				print("%s\\%s : %s" % (domain, username, sid))
			
		except SMBException as e:
			logger.debug(traceback.format_exc())
			print(e.pprint())
		except SMBMachineException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
		except DCERPCException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
		except Exception as e:
			traceback.print_exc()

	async def do_use(self, share_name):
		"""selects share to be used"""
		try:
			if self.is_anon is False:
				#anonymous connection might not have access to IPC$ so we are skipping the check
				if len(self.shares) == 0:
					_, err = await self.do_shares(show = False)
					if err is not None:
						raise err

				if share_name not in self.shares:
					if share_name.upper() not in self.shares:
						print('Error! Uknown share name %s' % share_name)
						return
					share_name = share_name.upper()

				self.__current_share = self.shares[share_name]
			else:
				self.__current_share = SMBShare.from_unc('\\\\%s\\%s' % (self.connection.target.get_hostname_or_ip(), share_name))
			_, err = await self.__current_share.connect(self.connection)
			if err is not None:
				raise err
			self.__current_directory = self.__current_share.subdirs[''] #this is the entry directory
			self.prompt = '[%s]$ ' % self.__current_directory.unc_path
			_, err = await self.do_refreshcurdir()
			if err is not None:
				raise err
			return True, None

		except SMBException as e:
			logger.debug(traceback.format_exc())
			print(e.pprint())
			return None, e
		except SMBMachineException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
			return None, e
		except DCERPCException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
			return None, e
		except Exception as e:
			traceback.print_exc()
			return None, e
			
	async def do_dir(self):
		return await self.do_ls()

	async def do_ls(self):
		try:
			if self.__current_share is None:
				print('No share selected!')
				return
			if self.__current_directory is None:
				print('No directory selected!')
				return
			
			for entry in self.__current_directory.get_console_output():
				print(entry)
			
			return True, None
		except SMBException as e:
			logger.debug(traceback.format_exc())
			print(e.pprint())
			return None, e
		except SMBMachineException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
			return None, e
		except DCERPCException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
			return None, e
		except Exception as e:
			traceback.print_exc()
			return None, e

	async def do_refreshcurdir(self):
		try:
			async for entry in self.machine.list_directory(self.__current_directory):
				#no need to put here anything, the dir bject will store the refreshed data
				a = 1
			
			return True, None
		except Exception as e:
			traceback.print_exc()
			return None, e

	async def do_cd(self, directory_name):
		try:
			if self.__current_share is None:
				print('No share selected!')
				return False, None
			if self.__current_directory is None:
				print('No directory selected!')
				return False, None
			
			if directory_name not in self.__current_directory.subdirs:
				if directory_name == '..':
					self.__current_directory = self.__current_directory.parent_dir
					self.prompt = '[%s] $' % (self.__current_directory.unc_path)
					return True, None
				else:
					print('The directory "%s" is not in parent directory "%s"' % (directory_name, self.__current_directory.fullpath))
					return False, None
			
			else:
				self.__current_directory = self.__current_directory.subdirs[directory_name]
				self.prompt = '[%s] $' % (self.__current_directory.unc_path)
				_, err = await self.do_refreshcurdir()
				if err is not None:
					raise err

				return True, None
			
		except SMBException as e:
			logger.debug(traceback.format_exc())
			print(e.pprint())
			return None, e
		except SMBMachineException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
			return None, e
		except DCERPCException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
			return None, e
		except Exception as e:
			traceback.print_exc()
			return None, e

	def get_current_dirs(self):
		if self.__current_directory is None:
			return []
		return list(self.__current_directory.subdirs.keys())

	def get_current_files(self):
		if self.__current_directory is None:
			return []
		return list(self.__current_directory.files.keys())

	async def do_getfilesd(self, file_name):
		try:
			if file_name not in self.__current_directory.files:
				print('file not in current directory!')
				return False, None
			file_obj = self.__current_directory.files[file_name]
			sd, err = await file_obj.get_security_descriptor(self.connection)
			if err is not None:
				raise err
			print(sd.to_sddl())
			return True, None

		except SMBException as e:
			logger.debug(traceback.format_exc())
			print(e.pprint())
			return None, e
		except SMBMachineException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
			return None, e
		except DCERPCException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
			return None, e
		except Exception as e:
			traceback.print_exc()
			return None, e

	async def do_getdirsd(self):
		try:
			sd, err = await self.__current_directory.get_security_descriptor(self.connection)
			if err is not None:
				raise err
			print(str(sd.to_sddl()))
			return True, None
		except SMBException as e:
			logger.debug(traceback.format_exc())
			print(e.pprint())
			return None, e
		except SMBMachineException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
			return None, e
		except DCERPCException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
			return None, e
		except Exception as e:
			traceback.print_exc()
			return None, e

	def _cd_completions(self):
		return SMBPathCompleter(get_current_dirs = self.get_current_dirs)

	def _get_completions(self):
		return SMBPathCompleter(get_current_dirs = self.get_current_files)
	
	def _del_completions(self):
		return SMBPathCompleter(get_current_dirs = self.get_current_files)
	
	def _sid_completions(self):
		return SMBPathCompleter(get_current_dirs = self.get_current_files)
	
	def _dirsid_completions(self):
		return SMBPathCompleter(get_current_dirs = self.get_current_dirs)


	async def do_services(self):
		"""Lists remote services"""
		try:
			async for service, err in self.machine.list_services():
				if err is not None:
					raise err
				print(service)
			
			return True, None
			
			
		except SMBException as e:
			logger.debug(traceback.format_exc())
			print(e.pprint())
			return None, e
		except SMBMachineException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
			return None, e
		except DCERPCException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
			return None, e
		except Exception as e:
			traceback.print_exc()
			return None, e

	async def do_serviceen(self, service_name):
		"""Enables a remote service"""
		try:
			res, err = await self.machine.enable_service(service_name)
			if err is not None:
				raise err
			print(res)
			return True, None
		
		except SMBException as e:
			logger.debug(traceback.format_exc())
			print(e.pprint())
			return None, e
		except SMBMachineException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
			return None, e
		except DCERPCException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
			return None, e
		except Exception as e:
			traceback.print_exc()
			return None, e

	async def do_servicecreate(self, service_name, command, display_name = None):
		"""Creates a remote service"""
		try:
			_, err = await self.machine.create_service(service_name, command, display_name)
			if err is not None:
				raise err
			print('Service created!')
			return True, None

		except SMBException as e:
			logger.debug(traceback.format_exc())
			print(e.pprint())
			return None, e
		except SMBMachineException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
			return None, e
		except DCERPCException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
			return None, e
		except Exception as e:
			traceback.print_exc()
			return None, e

	async def do_servicedeploy(self, path_to_exec, remote_path):
		"""Deploys a binary file from the local system as a service on the remote system"""
		#servicedeploy /home/devel/Desktop/cmd.exe /shared/a.exe
		try:
			basename = ntpath.basename(remote_path)
			remote_path = '\\\\%s\\%s\\%s\\%s' % (self.connection.target.get_hostname_or_ip(), self.__current_share.name, self.__current_directory.fullpath , basename)
			_, err = await self.machine.deploy_service(path_to_exec, remote_path = remote_path)
			if err is not None:
				raise err
			print('Service deployed!')
			return True, None

		except SMBException as e:
			logger.debug(traceback.format_exc())
			print(e.pprint())
			return None, e
		except SMBMachineException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
			return None, e
		except DCERPCException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
			return None, e
		except Exception as e:
			traceback.print_exc()
			return None, e

	async def do_put(self, file_name):
		"""Uploads a file to the remote share"""
		try:
			basename = ntpath.basename(file_name)
			dst = '\\%s\\%s\\%s' % (self.__current_share.name, self.__current_directory.fullpath , basename)
			_, err = await self.machine.put_file(file_name, dst)
			if err is not None:
				print('Failed to put file! Reason: %s' % err)
				return False, err
			print('File uploaded!')
			_, err = await self.do_refreshcurdir()
			if err is not None:
				raise err
			
			return True, None

		except SMBException as e:
			logger.debug(traceback.format_exc())
			print(e.pprint())
			return None, e
		except SMBMachineException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
			return None, e
		except DCERPCException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
			return None, e
		except Exception as e:
			traceback.print_exc()
			return None, e

	async def do_del(self, file_name):
		"""Removes a file from the remote share"""
		try:
			basename = ntpath.basename(file_name)
			dst = '\\%s\\%s\\%s' % (self.__current_share.name, self.__current_directory.fullpath , basename)
			_, err = await self.machine.del_file(dst)
			if err is not None:
				raise err
			print('File deleted!')
			_, err = await self.do_refreshcurdir()
			if err is not None:
				raise err
			return True, None

		except SMBException as e:
			logger.debug(traceback.format_exc())
			print(e.pprint())
			return None, e
		except SMBMachineException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
			return None, e
		except DCERPCException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
			return None, e
		except Exception as e:
			traceback.print_exc()
			return None, e

	async def do_regsave(self, hive_name, file_path):
		"""Saves a registry hive to a file on remote share"""
		try:
			_, err = await self.machine.save_registry_hive(hive_name, file_path)
			if err is not None:
				raise err
			print('Hive saved!')
			return True, None
		
		except SMBException as e:
			logger.debug(traceback.format_exc())
			print(e.pprint())
			return None, e
		except SMBMachineException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
			return None, e
		except DCERPCException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
			return None, e
		except Exception as e:
			traceback.print_exc()
			return None, e


	async def do_get(self, file_name):
		"""Download a file from the remote share to the current folder"""
		try:
			matched = []
			if file_name not in self.__current_directory.files:
				
				for fn in fnmatch.filter(list(self.__current_directory.files.keys()), file_name):
					matched.append(fn)
				if len(matched) == 0:
					print('File with name %s is not present in the directory %s' % (file_name, self.__current_directory.name))
					return False, None
			else:
				matched.append(file_name)
			
			for file_name in matched:
				file_obj = self.__current_directory.files[file_name]
				with tqdm.tqdm(desc = 'Downloading %s' % file_name, total=file_obj.size, unit='B', unit_scale=True, unit_divisor=1024) as pbar:
					with open(file_name, 'wb') as outfile:
						async for data, err in self.machine.get_file_data(file_obj):
							if err is not None:
								raise err
							if data is None:
								break
							outfile.write(data)
							pbar.update(len(data))
			return True, None
		except SMBException as e:
			logger.debug(traceback.format_exc())
			print(e.pprint())
			return None, e
		except SMBMachineException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
			return None, e
		except DCERPCException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
			return None, e
		except Exception as e:
			traceback.print_exc()
			return None, e


	
	async def do_mkdir(self, directory_name):
		"""Creates a directory on the remote share"""
		try:
			_, err = await self.machine.create_subdirectory(directory_name, self.__current_directory)
			if err is not None:
				raise err
			print('Directory created!')
			_, err = await self.do_refreshcurdir()
			if err is not None:
				raise err
			return True, None

		except SMBException as e:
			logger.debug(traceback.format_exc())
			print(e.pprint())
			return None, e
		except SMBMachineException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
			return None, e
		except DCERPCException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
			return None, e
		except Exception as e:
			traceback.print_exc()
			return None, e

	async def do_dcsync(self, username = None):
		"""It's a suprse tool that will help us later"""
		try:
			users = []
			if username is not None:
				users.append(username)
			async for secret, err in self.machine.dcsync(target_users=users):
				if err is not None:
					raise err
				print(str(secret))
			
			return True, None
		
		except SMBException as e:
			logger.debug(traceback.format_exc())
			print(e.pprint())
			return None, e
		except SMBMachineException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
			return None, e
		except DCERPCException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
			return None, e
		except Exception as e:
			traceback.print_exc()
			return None, e

	async def do_users(self, domain = None):
		"""List users in domain"""
		try:
			async for username, user_sid, err in self.machine.list_domain_users(domain):
				if err is not None:
					print(str(err))
				print('%s %s' % (username, user_sid))
			
			return True, None
		
		except SMBException as e:
			logger.debug(traceback.format_exc())
			print(e.pprint())
			return None, e
		except SMBMachineException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
			return None, e
		except DCERPCException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
			return None, e
		except Exception as e:
			traceback.print_exc()
			return None, e

	async def do_printerbug(self, attacker_ip):
		"""Printerbug"""
		try:
			res, err = await self.machine.printerbug(attacker_ip)
			if err is not None:
				print(str(err))
			print(res)
		
			return True, None
		
		except SMBException as e:
			logger.debug(traceback.format_exc())
			print(e.pprint())
			return None, e
		except SMBMachineException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
			return None, e
		except DCERPCException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
			return None, e
		except Exception as e:
			traceback.print_exc()
			return None, e

	async def do_tasks(self):
		"""List scheduled tasks """
		try:
			async for taskname, err in await self.machine.tasks_list():
				if err is not None:
					raise err
				print(taskname)
			
			return True, None
		
		except SMBException as e:
			logger.debug(traceback.format_exc())
			print(e.pprint())
			return None, e
		except SMBMachineException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
			return None, e
		except DCERPCException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
			return None, e
		except Exception as e:
			traceback.print_exc()
			return None, e

	async def do_taskregister(self, template_file, task_name = None):
		"""Registers a new scheduled task"""
		try:
			with open(template_file, 'r') as f:
				template = f.read()

			res, err = await self.machine.tasks_register(template, task_name = task_name)
			if err is not None:
				logger.info('[!] Failed to register new task!')
				raise err
		
			return True, None
		
		except SMBException as e:
			logger.debug(traceback.format_exc())
			print(e.pprint())
			return None, e
		except SMBMachineException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
			return None, e
		except DCERPCException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
			return None, e
		except Exception as e:
			traceback.print_exc()
			return None, e

	async def do_taskdel(self, task_name):
		"""Deletes a scheduled task	"""
		try:
			_, err = await self.machine.tasks_delete(task_name)
			if err is not None:
				raise err

			return True, None
		
		except SMBException as e:
			logger.debug(traceback.format_exc())
			print(e.pprint())
			return None, e
		except SMBMachineException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
			return None, e
		except DCERPCException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
			return None, e
		except Exception as e:
			traceback.print_exc()
			return None, e


	async def do_taskcmdexec(self, command):
		""" Executes a shell command using the scheduled tasks service"""
		try:
			await self.machine.tasks_execute_commands([command])
		except SMBException as e:
			logger.debug(traceback.format_exc())
			print(e.pprint())
		except SMBMachineException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
		except DCERPCException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
		except Exception as e:
			traceback.print_exc()

	async def do_interfaces(self):
		""" Lists all network interfaces of the remote machine """
		try:
			interfaces, err = await self.machine.list_interfaces()
			if err is not None:
				raise err
			for iface in interfaces:
				print('%d: %s' % (iface['index'], iface['address']))
			
			return True, None
		
		except SMBException as e:
			logger.debug(traceback.format_exc())
			print(e.pprint())
			return None, e
		except SMBMachineException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
			return None, e
		except DCERPCException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
			return None, e
		except Exception as e:
			traceback.print_exc()
			return None, e

	async def do_enumall(self, depth = 3):
		""" Enumerates all shares for all files and folders recursively """
		try:
			depth = int(depth)
			async for path, otype, err in self.machine.enum_all_recursively(depth = depth):
				if otype is not None:
					print('[%s] %s' % (otype[0].upper(), path))
				if err is not None:
					print('[E] %s %s' % (err, path))

			return True, None
		except SMBException as e:
			logger.debug(traceback.format_exc())
			print(e.pprint())
			return None, e
		except SMBMachineException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
			return None, e
		except DCERPCException as e:
			logger.debug(traceback.format_exc())
			print(str(e))
			return None, e
		except Exception as e:
			traceback.print_exc()
			return None, e

async def amain(args):
	client = SMBClient(args.smb_url, silent = args.silent)
	if len(args.commands) == 0:
		if args.no_interactive is True:
			print('Not starting interactive!')
			return
		await client.run()
	else:
		for command in args.commands:
			if command == 'i':
				await client.run()
				return
			
			cmd = shlex.split(command)
			#print(cmd)
			if cmd[0] == 'login':
				_, err = await client.do_login()
				if err is not None:
					return
				continue
			
			await client._run_single_command(cmd[0], cmd[1:])
		await client.do_logout()

def main():
	import argparse
	import platform
	import logging
	
	parser = argparse.ArgumentParser(description='Interactive SMB client')
	parser.add_argument('-v', '--verbose', action='count', default=0)
	parser.add_argument('-s', '--silent', action='store_true', help='do not print banner')
	parser.add_argument('-n', '--no-interactive', action='store_true')
	parser.add_argument('smb_url', help = 'Connection string that describes the authentication and target. Example: smb+ntlm-password://TEST\\Administrator:password@10.10.10.2')
	parser.add_argument('commands', nargs='*')
	
	args = parser.parse_args()
	if args.silent is False:
		print(__banner__)

	if args.verbose >=1:
		logger.setLevel(logging.DEBUG)

	if args.verbose > 2:
		print('setting deepdebug')
		logger.setLevel(1) #enabling deep debug
		sockslogger.setLevel(1)
		asyncio.get_event_loop().set_debug(True)
		logging.basicConfig(level=logging.DEBUG)

	asyncio.run(amain(args))

if __name__ == '__main__':
	main()
	
	

	