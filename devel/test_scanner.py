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
		"""
		Connection MUST NOT be initialized!!!!
		"""
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
		
	async def fake_logon(self):
		"""
		Initiates NTLM authentication, but disconnects after the server sent the CHALLENGE message.
		Useful for getting info on the server without having valid user creds
		"""
		extra_info = await self.connection.fake_login()
		print(extra_info)
		if self.results_queue is not None:
			await self.results_queue.put(extra_info)
		else:
			self.hostinfo.finger_info = extra_info
		
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
		
		await self.fake_logon()
		#await self.list_shares()
		#for share in self.hostinfo.shares:
		#	if share.name in ['IPC$', 'ADMIN$']:
		#		continue
		#	await self.enumerate_share(share)
		#await self.enumerate_sessions()
		#await self.enumerate_groups()
		
		
class SMBScanCommandFinger:
	def __init__(self, credential = None, target = None):
		self.credential = credential
		self.target = target
		
class SMBScanResultFinger:
	def __init__(self):
		self.extrainfo = None

class SMBScanCommandListShares:
	def __init__(self):
		self.credential = None
		self.target = None
		
class SMBScanResultListShares:
	def __init__(self):
		self.shares = {}
		
class SMBScanCommandListEnumShares:
	def __init__(self):
		self.credential = None
		self.target = None
		self.max_depth = None
		self.skip_shares = {}
		self.skip_folders = {}
		self.grab_sids = True
		
class SMBScanCommandEnumSessions:
	def __init__(self):
		self.credential = None
		self.target = None
		
class SMBScanResultEnumSessions:
	def __init__(self):
		self.sessions = {}
		
class SMBScanCommandEnumLocalGroups:
	def __init__(self):
		self.credential = None
		self.target = None
		self.group_rids = {}
		
class SMBScanResultEnumLocalGroups:
	def __init__(self):
		self.groups = {}
		
class SMBScanCommandEnumServices:
	def __init__(self):
		self.credential = None
		self.target = None
		
class SMBScanResultEnumServices:
	def __init__(self):
		self.services = {}
		
class SMBScanCommandEnumSchedTasks:
	def __init__(self):
		self.credential = None
		self.target = None
		
class SMBScanResultEnumSchedTasks:
	def __init__(self):
		self.tasks = {}
		
class SMBScanCommandEnumNetworkInterfaces:
	def __init__(self):
		self.credential = None
		self.target = None
		
class SMBScanResultEnumNetworkInterfaces:
	def __init__(self):
		self.interfaces = None
		
class SMBScanScannerSetup:
	def __init__(self):
		self.max_workers = None
		
class SMBScanScannerStop:
	def __init__(self):
		self.a = None
		
class SMBScanTask:
	def __init__(self, target, credential = None, commands = []):
		self.target = target
		self.credential = credential
		self.commands = commands
		
		
class SMBScanWorker:
	def __init__(self, work_queue, results_queue, shutdown_evt = asyncio.Event()):
		self.work_queue = work_queue
		self.results_queue = results_queue
		self.shutdown_evt = shutdown_evt
		
	async def run(self):
		while not self.shutdown_evt.is_set():
			
			get_task = asyncio.create_task(self.work_queue.get())
			shutdown_task = asyncio.create_task(self.shutdown_evt.wait())
			done, pending = await asyncio.wait([get_task, shutdown_task], return_when = asyncio.FIRST_COMPLETED)
			if shutdown_task in done:
				print('shutdown!')
				return
			if get_task in done:
				job = await get_task
				input('SMBScanWorker run %s' % job)
				try:
					#TODO:
					result = None
					
					
				except Exception as e:
					print(e)
				
				else:
					await self.results_queue.put(result)
		
class SMBScanner:
	def __init__(self, config):
		self.config = config
		
		######### FROM CONFIG
		self.command_queue = None
		self.results_queue = None
		
		######### INTERNAL
		self.work_queue = asyncio.Queue()
		self.work_results = asyncio.Queue()
		self.shutdown_evt = asyncio.Event()
		self.dispatch_results_task = None
		
		######### FROM SETUP COMMAND
		self.max_workers = 0
		self.worker_tasks = []
		
	async def setup(self, setup_cmd):
		self.max_workers = setup_cmd.max_workers
		
		for i in range(self.max_workers):
			worker = SMBScanWorker(self.work_queue, self.work_results, self.shutdown_evt)
			self.worker_tasks.append(asyncio.create_task(worker.run()))
		
	async def run(self):
		if self.config['mode'] == 'INTERNAL':
			self.command_queue = self.config['command_queue']
			self.results_queue = self.config['results_queue']
		
		else:
			raise Exception('Not implemented!')
			return
		
		self.dispatch_results_task = asyncio.ensure_future(self.dispatch_results())
		asyncio.ensure_future(self.fetch_commands())
		
		
		
		
	async def fetch_commands(self):
		while not self.shutdown_evt.is_set():
			cmd = await self.command_queue.get()
			if isinstance(cmd, SMBScanScannerSetup):
				await self.setup(cmd)
				
			elif isinstance(cmd, SMBScanScannerStop):
				print('SMBScanner shutting down!')
				self.shutdown_evt.set()
				try:
					await asyncio.wait_for(asyncio.gather(*self.worker_tasks), timeout = 1)
				except asyncio.TimeoutError:
					for task in self.worker_tasks:
						task.cancel()
				print('All workers finished!')
				self.dispatch_results_task.cancel()
				return
			
			else:
				print('fetch_commands : %s' % cmd)
				job = cmd
				await self.work_queue.put(job)
			
	async def dispatch_results(self):
		while not self.shutdown_evt.is_set():
			result = await self.work_results.get()
			await self.results_queue.put(result)
	
			
		
class SMBScannerManager:
	def __init__(self, max_workers = 200, tasks = [], tasks_queue = None):
		#self.spnego = spnego
		self.tasks = tasks
		self.tasks_queue = tasks_queue
		self.max_workers = max_workers
		
		self.scanners_in_q = asyncio.Queue()
		self.scanners_out_q = asyncio.Queue()
		self.shutdown_evt = asyncio.Event()
		self.scanner = None
		
		self.__command_queue = asyncio.Queue()
		self.__results_queue = asyncio.Queue()
	
	async def run_internal(self):
		config= {
			'mode' : 'INTERNAL',
			'command_queue' : self.scanners_out_q,
			'results_queue' : self.scanners_in_q,
		}
		
		self.scanner = SMBScanner(config)
		await self.scanner.run()
		
		ss = SMBScanScannerSetup()
		ss.max_workers = self.max_workers
		await self.__command_queue.put(ss)
		
		asyncio.ensure_future(self.send_tasks())
		asyncio.ensure_future(self.process_results())
		
		asyncio.ensure_future(self.dispatch_tasks())
		
		await self.shutdown_evt.wait()
		
	async def dispatch_tasks(self):
		for task in self.tasks:
			await self.__command_queue.put(task)
			
		if self.tasks_queue is not None:
			while True:
				task = await self.tasks_queue.get()
				await self.__command_queue.put(task)
		
	async def send_tasks(self):
		while not self.shutdown_evt.is_set():
			job = await self.__command_queue.get()
			print('send_tasks %s' % str(job))
			await self.scanners_out_q.put(job)
		
		
	async def process_results(self):
		while not self.shutdown_evt.is_set():
			res = await asyncio.gather(*[self.__results_queue.get(), self.shutdown_evt.wait()], return_exceptions = True)
			print('send_tasks %s' % str(res))

async def scanmanager_test(connection_string):
	target = SMBTarget.from_connection_string(connection_string)
	credential = SMBCredential.from_connection_string(connection_string)
	command = SMBScanCommandFinger()
	
	task = SMBScanTask(target, credential = credential, commands = [command])
	
	sm = SMBScannerManager(tasks = [task])
	await sm.run_internal()

async def filereader_test(connection_string, filename):
	target = SMBTarget.from_connection_string(connection_string)
	credential = SMBCredential.from_connection_string(connection_string)
	
	spneg = AuthenticatorBuilder.to_spnego_cred(credential, target)
	
	async with SMBConnection(spneg, target) as connection:
		
		#try:
		#	await connection.login()
		#except Exception as e:
		#	print(str(e))
		#	raise e
			
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
	
	
	#asyncio.run(filereader_test(connection_string, filename))
	asyncio.run(scanmanager_test(connection_string))
	
	
	'TODO: TEST NT hash with ntlm!'