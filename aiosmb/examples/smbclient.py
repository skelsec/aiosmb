import asyncio
import traceback
import ntpath
import fnmatch

import tqdm
from aiocmd import aiocmd
from aiosmb.examples.smbpathcompleter import SMBPathCompleter

from aiosmb import logger
from aiosmb.commons.connection.url import SMBConnectionURL
from aiosmb.commons.interfaces.machine import SMBMachine
from aiosmb.commons.utils.decorators import rr, rr_gen, red, red_gen, ef_gen


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
	def __init__(self, url = None):
		aiocmd.PromptToolkitCmd.__init__(self, ignore_sigint=False) #Setting this to false, since True doesnt work on windows...
		self.conn_url = None
		if url is not None:
			self.conn_url = SMBConnectionURL(url)
		self.connection = None
		self.machine = None

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
			
			self.connection  = self.conn_url.get_connection()
			
			logger.debug(self.conn_url.get_credential())
			logger.debug(self.conn_url.get_target())

			await self.connection.login()
			self.machine = SMBMachine(self.connection)
		except Exception as e:
			traceback.print_exc()
		else:
			print('Login success')

	async def do_shares(self, show = True):
		"""Lists available shares"""
		try:
			async for share, _ in ef_gen(self.machine.list_shares()):
				self.shares[share.name] = share
				if show is True:
					print(share.name)
				
		except Exception as e:
			traceback.print_exc()

	async def do_sessions(self):
		"""Lists sessions of connected users"""
		try:
			async for sess, _ in ef_gen(self.machine.list_sessions()):
				print("%s : %s" % (sess.username, sess.ip_addr))
		except Exception as e:
			traceback.print_exc()

	async def do_domains(self):
		"""Lists domain"""
		try:
			async for domain, _ in self.machine.list_domains():
				print(domain)
		except Exception as e:
			traceback.print_exc()

	async def do_localgroups(self):
		"""Lists local groups"""
		try:
			async for name, sid, _ in self.machine.list_localgroups():
				print("%s : %s" % (name, sid))
		except Exception as e:
			traceback.print_exc()
	
	async def do_domaingroups(self, domain_name):
		"""Lists groups in a domain"""
		try:
			async for name, sid, _ in self.machine.list_groups(domain_name):
				print("%s : %s" % (name, sid))
		except Exception as e:
			traceback.print_exc()
	
	async def do_groupmembers(self, domain_name, group_name):
		"""Lists members of an arbitrary group"""
		try:
			async for domain, username, sid, _ in self.machine.list_group_members(domain_name, group_name):
				print("%s\\%s : %s" % (domain, username, sid))
		except Exception as e:
			traceback.print_exc()

	async def do_localgroupmembers(self, group_name):
		"""Lists members of a local group"""
		try:
			async for domain, username, sid, _ in self.machine.list_group_members('Builtin', group_name):
				print("%s\\%s : %s" % (domain, username, sid))
		except Exception as e:
			traceback.print_exc()

	async def do_use(self, share_name):
		"""selects share to be used"""
		try:
			if len(self.shares) == 0:
				await self.do_shares(show = False)

			if share_name not in self.shares:
				if share_name.upper() not in self.shares:
					print('Error! Uknown share name %s' % share_name)
					return
				share_name = share_name.upper()

			self.__current_share = self.shares[share_name]
			await self.__current_share.connect(self.connection)
			self.__current_directory = self.__current_share.subdirs[''] #this is the entry directory
			self.prompt = '[%s] $' % self.__current_directory.unc_path
			await self.do_ls(False)

		except Exception as e:
			traceback.print_exc()
	
	async def do_ls(self, show = True):
		try:
			if self.__current_share is None:
				print('No share selected!')
				return
			if self.__current_directory is None:
				print('No directory selected!')
				return
			
			#print(self.__current_directory)
			async for entry in self.machine.list_directory(self.__current_directory):
				if show == True:
					print(entry)
		except Exception as e:
			traceback.print_exc()

	async def do_cd(self, directory_name):
		try:
			if self.__current_share is None:
				print('No share selected!')
				return
			if self.__current_directory is None:
				print('No directory selected!')
				return
			
			if directory_name not in self.__current_directory.subdirs:
				if directory_name == '..':
					self.__current_directory = self.__current_directory.parent_dir
					self.prompt = '[%s] $' % (self.__current_directory.unc_path)
					return
				else:
					print('The directory "%s" is not in parent directory "%s"' % (directory_name, self.__current_directory.fullpath))
			
			else:
				self.__current_directory = self.__current_directory.subdirs[directory_name]
				self.prompt = '[%s] $' % (self.__current_directory.unc_path)
				await self.do_ls(False)
			
		except Exception as e:
			traceback.print_exc()

	def get_current_dirs(self):
		if self.__current_directory is None:
			return []
		return list(self.__current_directory.subdirs.keys())

	def get_current_files(self):
		if self.__current_directory is None:
			return []
		return list(self.__current_directory.files.keys())

	def _cd_completions(self):
		return SMBPathCompleter(get_current_dirs = self.get_current_dirs)

	def _get_completions(self):
		return SMBPathCompleter(get_current_dirs = self.get_current_files)

	async def do_services(self):
		"""Lists remote services"""
		try:
			async for service, _ in self.machine.list_services():
				print(service)
			
		except Exception as e:
			traceback.print_exc()

	async def do_serviceen(self, service_name):
		"""Enables a remote service"""
		try:
			res, _ = await self.machine.enable_service(service_name)
			print(res)
		except Exception as e:
			traceback.print_exc()

	async def do_servicecreate(self, service_name, command, display_name = None):
		"""Creates a remote service"""
		try:
			res, _ = await self.machine.create_service(service_name, command, display_name)
		except Exception as e:
			traceback.print_exc()

	async def do_servicedeploy(self, path_to_exec, remote_path):
		"""Deploys a binary file from the local system as a service on the remote system"""
		#servicedeploy /home/devel/Desktop/cmd.exe /shared/a.exe
		try:
			basename = ntpath.basename(remote_path)
			remote_path = '\\\\%s\\%s\\%s\\%s' % (self.connection.target.get_hostname_or_ip(), self.__current_share.name, self.__current_directory.fullpath , basename)
			await rr(self.machine.deploy_service(path_to_exec, remote_path = remote_path))
		except Exception as e:
			traceback.print_exc()		

	async def do_put(self, file_name):
		"""Uploads a file to the remote share"""
		try:
			basename = ntpath.basename(file_name)
			dst = '\\%s\\%s\\%s' % (self.__current_share.name, self.__current_directory.fullpath , basename)
			print(basename)
			print(dst)
			await self.machine.put_file(file_name, dst)
			
		except Exception as e:
			traceback.print_exc()

	async def do_del(self, file_name):
		"""Removes a file from the remote share"""
		try:
			basename = ntpath.basename(file_name)
			dst = '\\%s\\%s\\%s' % (self.__current_share.name, self.__current_directory.fullpath , basename)
			print(dst)
			await self.machine.del_file(dst)
			
		except Exception as e:
			traceback.print_exc()

	async def do_regsave(self, hive_name, file_path):
		"""Saves a registry hive to a file on remote share"""
		try:
			await rr(self.machine.save_registry_hive(hive_name, file_path))
		except Exception as e:
			traceback.print_exc()

	async def do_get(self, file_name):
		"""Download a file from the remote share to the current folder"""
		try:
			matched = []
			if file_name not in self.__current_directory.files:
				
				for fn in fnmatch.filter(list(self.__current_directory.files.keys()), file_name):
					matched.append(fn)
				if len(matched) == 0:
					print('File with name %s is not present in the directory %s' % (file_name, self.__current_directory.name))
					return
			else:
				matched.append(file_name)
			
			for file_name in matched:
				file_obj = self.__current_directory.files[file_name]
				with tqdm.tqdm(desc = 'Downloading %s' % file_name, total=file_obj.size, unit='B', unit_scale=True, unit_divisor=1024) as pbar:
					with open(file_name, 'wb') as outfile:
						async for data in self.machine.get_file_data(file_obj):
							if data is None:
								break
							outfile.write(data)
							pbar.update(len(data))
	
		except Exception as e:
			traceback.print_exc()

	
	async def do_mkdir(self, directory_name):
		"""Creates a directory on the remote share"""
		try:
			await self.machine.create_subdirectory(directory_name, self.__current_directory)

		except Exception as e:
			traceback.print_exc()

	async def do_dcsync(self):
		"""It's a suprse tool that will help us later"""
		try:
			async for secret, _ in rr_gen(self.machine.dcsync()):
				print(str(secret))
		except Exception as e:
			traceback.print_exc()

def main():
	import argparse
	import platform
	
	parser = argparse.ArgumentParser(description='Interactive SMB client')
	parser.add_argument('-v', '--verbose', action='count', default=0)
	parser.add_argument('smb_url', help = 'Connection string that describes the authentication and target. Example: smb+ntlm-password://TEST\\Administrator:password@10.10.10.2')
	
	args = parser.parse_args()

	if args.verbose > 2:
		print('setting deepdebug')
		logger.setLevel(1) #enabling deep debug

	asyncio.get_event_loop().run_until_complete(SMBClient(args.smb_url).run())

if __name__ == '__main__':
	main()
	
	

	