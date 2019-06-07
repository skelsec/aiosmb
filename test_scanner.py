import asyncio

import enum
import os

from aiosmb.commons.smbcontainer import *
from aiosmb.commons.smbcredential import SMBCredential
from aiosmb.commons.smbtarget import SMBTarget
from aiosmb.smbconnection import SMBConnection
from aiosmb.smbfilesystem import SMBFileSystem
from aiosmb.commons.authenticator_builder import AuthenticatorBuilder
from aiosmb.dcerpc.v5.transport.smbtransport import SMBTransport
from aiosmb.dcerpc.v5.interfaces.srvsmgr import SMBSRVS
from aiosmb.dcerpc.v5.interfaces.samrmgr import SMBSAMR

#import sys
#import traceback
#
#class TracePrints(object):
#	def __init__(self):    
#		self.stdout = sys.stdout
#	def write(self, s):
#		self.stdout.write("Writing %r\n" % s)
#		traceback.print_stack(file=self.stdout)
#		
#sys.stdout = TracePrints()
				
class SMBADScanner:
	def __init__(self, connection):
		self.connection = connection
		
	async def connect(self):
		await self.connection.login()
		
	async def enumerate_domains(self):
		"""
		Enumerates all domains 
		"""
		raise Exception('Not implemented')
		
		
	async def enumerate_users(self, domain):
		"""
		Enumerates all AD users in the given domain
		"""
		raise Exception('Not implemented')
		
	async def enumerate_machines(self, domain):
		"""
		Enumerates all AD users in the given domain
		"""
		raise Exception('Not implemented')
		
	async def enumerate_groups(self, domain):
		"""
		Enumerates all AD groups in the given domain
		"""
		raise Exception('Not implemented')
		
	async def enumerate_user_group_memberships(self, domain):
		"""
		Enumerates all AD groups in the given domain
		"""
		raise Exception('Not implemented')
		
	
	
class SMBHostScanner:
	def __init__(self, connection, results_queue = None):
		self.connection = connection
		self.hostinfo = SMBHostInfo()
		self.results_queue = results_queue
		
		self.fs = SMBFileSystem(connection)
		
		self.srvs = None
		self.srvs_works = True
		self.samr = None
		self.samr_works = True
		
	async def connect(self):
		await self.connection.login()
		
	async def open_srvs(self):
		if self.srvs_works == False:
			return
		self.srvs = SMBSRVS(self.connection)
		try:
			await self.srvs.connect()
		except Exception as e:
			print('open_srvs error: %s' % e)
			self.srvs_works = False
		else:
			self.srvs_works = True
		
	async def open_samr(self):
		if self.samr_works == False:
			return
		self.samr = SMBSAMR(self.connection)
		try:
			await self.samr.connect()
		
		except Exception as e:
			print('open_samr error: %s' % e)
			self.samr_works = False
		else:
			self.samr_works = True
		
	async def list_shares(self):
		"""
		Lists all available shares on the host
		"""
		if not self.srvs:
			await self.open_srvs()
		
		async for name, share_type, remark in self.srvs.list_shares():
			share = SMBShare(name, share_type, remark, fullpath = '\\\\%s\\%s' % (self.connection.target.get_ip(), name))
			self.hostinfo.shares.append(share)
		
			if self.results_queue is not None:
				await self.results_queue.put(share)
				
		
	async def enumerate_share(self, share):
		"""
		Enumerates all active user sessions on the host
		"""
		try:
			await self.fs.connect_share(share)
		except Exception as e:
			return
		for directory_name in share.subdirs:
			async for directory in self.fs.enumerate_directory_stack(share.subdirs[directory_name], maxdepth = 4, with_sid = True):
				if self.results_queue is not None:
					await self.results_queue.put(directory)
	
	async def enumerate_sessions(self):
		"""
		Enumerates all active user sessions on the host
		"""
		if not self.srvs:
			await self.open_srvs()
		if self.srvs_works == False:
			return
			
		try:
			async for user, ip in self.srvs.list_sessions():
				session = SMBUserSession(user, ip)
				if self.results_queue is not None:
					await self.results_queue.put(session)
				
				self.hostinfo.sessions.append(session)
		except Exception as e:
			print(e)
			return
		
	async def enumerate_groups(self):
		"""
		Enumerates the LOCAL groups on the host
		"""
		if not self.samr:
			await self.open_samr()
		
		print(self.samr_works)
		if self.samr_works == False:
			return
		
		
		local_domain_sid = await self.samr.get_domain_sid('Builtin')
		print('local_domain_sid : %s' % local_domain_sid)
		domain_handle = await self.samr.open_domain(local_domain_sid)
		async for groupname, sid in self.samr.list_domain_groups(domain_handle):
			lg = SMBLocalGroup(groupname, sid)
			
			alias_handle = await self.samr.open_alias(domain_handle, sid.split('-')[-1])
			print('alias_handle : %s' % alias_handle)
			async for sid in self.samr.list_alias_members(alias_handle):
				lg.members[sid] = 1
				
			if self.results_queue is not None:
				await self.results_queue.put(lg)
			
			self.hostinfo.groups.append(lg)
		
	async def enumerate_services(self):
		raise Exception('Not implemented')
		
	async def enumerate_tasks(self):
		raise Exception('Not implemented')
		
	
	async def run(self):
		
		await self.list_shares()
		for share in self.hostinfo.shares:
			if share.name in ['IPC$', 'ADMIN$']:
				continue
			await self.enumerate_share(share)
		await self.enumerate_sessions()
		await self.enumerate_groups()
		
		
class SMBScanner:
	def __init__(self, spnego, max_workers = 200, targets = None, targets_queue = None, results_queue = None):
		self.spnego = spnego
		self.targets = targets
		self.targets_queue = targets_queue
		self.results_queue = results_queue
		self.scan_finished = asyncio.Event()
		
		self.__scan_queue = asyncio.Queue()
		self.__result_queue = asyncio.Queue()
		self.max_workers = max_workers
		
		self.shutdown_evt = asyncio.Event()
		self.worker_tasks = []
		
		self.scan_type = 'QUEUE'
		
	async def scan_worker(self):
		while not self.shutdown_evt.is_set():
			host_scanner = await self.targets_queue.get()
			try:
				res = await host_scanner.run()
			except Exception as e:
				print('scan_worker error: %s' % e)
			else:
				if res is None:
					continue
				await self.__result_queue.put(res)
	

	async def run_queue(self):
		for i in range(self.max_workers):
			self.worker_tasks.append(asyncio.create_task(self.scan_worker()))
		
		while not self.shutdown_evt.is_set():
			target = await self.targets_queue.get()
			if target is None:
				break
			
		await asyncio.gather(*self.worker_tasks, return_exceptions=True)
		print('scan finished!')
		
		
		

async def filereader_test(connection_string, filename):
	target = SMBTarget.from_connection_string(connection_string)
	credential = SMBCredential.from_connection_string(connection_string)
	
	spneg = AuthenticatorBuilder.to_spnego_cred(credential, target)
	
	async with SMBConnection(spneg, target) as connection:
		
		try:
			await connection.login()
		except Exception as e:
			print(str(e))
			raise e
			
		results_queue =asyncio.Queue()
		host_scanner = SMBHostScanner(connection, results_queue = results_queue)
		
		await host_scanner.run()
		
		while True:
			res = await results_queue.get()
			
			print(type(res))
			print(res)
	
if __name__ == '__main__':
	connection_string = 'TEST/victim/ntlm/password:Passw0rd!1@10.10.10.2'	
	#connection_string = 'TEST/Administrator/ntlm/password:QLFbT8zkiFGlJuf0B3Qq@win2019ad.test.corp/10.10.10.2'
	#connection_string = 'TEST/Administrator/sspi-ntlm/password:QLFbT8zkiFGlJuf0B3Qq@win2019ad.test.corp/10.10.10.2'
	#connection_string = 'TEST/Administrator/kerberos/password:QLFbT8zkiFGlJuf0B3Qq@win2019ad.test.corp/10.10.10.2'
	#connection_string = 'TEST.corp/Administrator/sspi-kerberos@win2019ad.test.corp/10.10.10.2'
	filename = '\\\\10.10.10.2\\Users\\Administrator\\Desktop\\smb_test\\testfile1.txt'
	
	
	asyncio.run(filereader_test(connection_string, filename))
	
	
	'TODO: TEST NT hash with ntlm!'