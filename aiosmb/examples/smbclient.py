import asyncio
import traceback
import ntpath

from aiocmd import aiocmd
from prompt_toolkit.completion import WordCompleter

from aiosmb import logger
from aiosmb.commons.connection.url import SMBConnectionURL
from aiosmb.commons.interfaces.machine import SMBMachine

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
		try:
			async for share in self.machine.list_shares():
				self.shares[share.name] = share
				if show is True:
					print(share.name)
				
		except Exception as e:
			traceback.print_exc()

	async def do_sessions(self):
		try:
			async for sess in self.machine.list_sessions():
				print("%s : %s" % (sess.username, sess.ip_addr))
		except Exception as e:
			traceback.print_exc()

	async def do_domains(self):
		try:
			async for domain in self.machine.list_domains():
				print(domain)
		except Exception as e:
			traceback.print_exc()

	async def do_localgroups(self):
		try:
			async for name, sid in self.machine.list_localgroups():
				print("%s : %s" % (name, sid))
		except Exception as e:
			traceback.print_exc()
	
	async def do_domaingroups(self, domain_name):
		try:
			async for name, sid in self.machine.list_groups(domain_name):
				print("%s : %s" % (name, sid))
		except Exception as e:
			traceback.print_exc()
	
	async def do_groupmembers(self, domain_name, group_name):
		try:
			async for domain, username, sid in self.machine.list_group_members(domain_name, group_name):
				print("%s\\%s : %s" % (domain, username, sid))
		except Exception as e:
			traceback.print_exc()

	async def do_localgroupmembers(self, group_name):
		try:
			async for domain, username, sid in self.machine.list_group_members('Builtin', group_name):
				print("%s\\%s : %s" % (domain, username, sid))
		except Exception as e:
			traceback.print_exc()

	async def do_use(self, share_name):
		try:
			if len(self.shares) == 0:
				await self.do_shares(show = False)

			if share_name in self.shares:
				self.__current_share = self.shares[share_name]
				await self.__current_share.connect(self.connection)
				self.__current_directory = self.__current_share.subdirs[''] #this is the entry directory
				
			else:
				print('Error! Uknown share name %s' % share_name)
		except Exception as e:
			traceback.print_exc()
	
	async def do_ls(self):
		try:
			if self.__current_share is None:
				print('No share selected!')
				return
			if self.__current_directory is None:
				print('No directory selected!')
				return
			
			print(self.__current_directory)
			async for entry in self.machine.list_directory(self.__current_directory):
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
				print('The directory "%s" is not in parent directory "%s"' % (directory_name, self.__current_directory.fullpath))
			
			else:
				self.__current_directory = self.__current_directory.subdirs[directory_name]
			
		except Exception as e:
			traceback.print_exc()

	async def do_services(self):
		try:
			async for service in self.machine.list_services():
				print(service)
			
		except Exception as e:
			traceback.print_exc()

	async def do_put(self, file_name):
		try:
			basename = ntpath.basename(file_name)
			dst = '\\\\%s\\%s\\%s\\%s' % (self.connection.target.get_hostname_or_ip(), self.__current_share.name, self.__current_directory.fullpath , basename)
			print(basename)
			print(dst)
			await self.machine.put_file_raw(file_name, dst)
			
		except Exception as e:
			traceback.print_exc()

	async def do_get(self, file_name):
		try:
			if file_name not in self.__current_directory.files:
				print('File with name %s is not present in the directory %s' % (file_name, self.__current_directory.name))
				return
			
			out_path = file_name
			await self.machine.get_file(out_path, self.__current_directory.files[file_name])

		except Exception as e:
			traceback.print_exc()

	async def do_mkdir(self, directory_name):
		try:
			await self.machine.create_subdirectory(directory_name, self.__current_directory)

		except Exception as e:
			traceback.print_exc()

	async def do_dcsync(self):
		try:
			async for secret in self.machine.dcsync():
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
	
	

	