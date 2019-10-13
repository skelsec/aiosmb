import enum
import asyncio

from aiosmb import logger
from aiosmb.dcerpc.v5.common.service import SMBServiceStatus, SMBService
from aiosmb.dcerpc.v5.transport.smbtransport import SMBTransport
from aiosmb.dcerpc.v5 import wkst, scmr

class SMBRemoteServieManager:
	def __init__(self, connection):
		self.connection = connection
		self.dce = None
		self.handle = None
		
		self.service_handles = {} #service_name -> handle
		
	async def __aenter__(self):
		return self
		
	async def __aexit__(self, exc_type, exc, traceback):
		await self.close()
		
	async def connect(self, open = True):
		rpctransport = SMBTransport(self.connection, filename=r'\svcctl')
		self.dce = rpctransport.get_dce_rpc()
		await self.dce.connect()
		await self.dce.bind(scmr.MSRPC_UUID_SCMR)

		if open == True:
			await self.open()
		
	async def open(self):
		if not self.dce:
			await self.connect()
		
		ans = await scmr.hROpenSCManagerW(self.dce)
		self.handle = ans['lpScHandle']
		
	async def close(self):
		if self.dce:
			if self.handle:
				for service_name in self.service_handles:
					try:
						await self.close_service(service_name)
					except:
						pass
				try:
					await scmr.hRCloseServiceHandle(self.dce, self.service_handles[service_name])
				except:
					pass
			try:
				await self.dce.disconnect()
			except:
				pass
			return

	async def list(self):
		resp = await scmr.hREnumServicesStatusW(self.dce, self.handle)
		for i in range(len(resp)):
			service_status = None
			state = resp[i]['ServiceStatus']['dwCurrentState']
			if state == scmr.SERVICE_CONTINUE_PENDING:
			   service_status = SMBServiceStatus.CONTINUE_PENDING
			elif state == scmr.SERVICE_PAUSE_PENDING:
			   service_status = SMBServiceStatus.PAUSE_PENDING
			elif state == scmr.SERVICE_PAUSED:
			   service_status = SMBServiceStatus.PAUSED
			elif state == scmr.SERVICE_RUNNING:
			   service_status = SMBServiceStatus.RUNNING
			elif state == scmr.SERVICE_START_PENDING:
			   service_status = SMBServiceStatus.START_PENDING
			elif state == scmr.SERVICE_STOP_PENDING:
			   service_status = SMBServiceStatus.STOP_PENDING
			elif state == scmr.SERVICE_STOPPED:
			   service_status = SMBServiceStatus.STOPPED
			else:
			   service_status = SMBServiceStatus.UNKNOWN

			service = SMBService(resp[i]['lpServiceName'][:-1], resp[i]['lpDisplayName'][:-1], service_status)
			yield service
			
	async def open_service(self, service_name):
		if service_name in self.service_handles:
			return
			
		ans = await scmr.hROpenServiceW(self.dce, self.handle, service_name)
		self.service_handles[service_name] = ans['lpServiceHandle']
		
	async def close_service(self, service_name):
		if not self.handle:
			await self.open()
		if service_name not in self.service_handles:
			await self.open_service(service_name)
		
		await scmr.hRCloseServiceHandle(self.dce, self.service_handles[service_name])
		del self.service_handles[service_name]
		
	async def check_service_status(self, service_name):
		if not self.handle:
			await self.open()
		if service_name not in self.service_handles:
			await self.open_service(service_name)
		
		# Let's check its status
		ans = await scmr.hRQueryServiceStatus(self.dce, self.service_handles[service_name])
		if ans['lpServiceStatus']['dwCurrentState'] == scmr.SERVICE_STOPPED:
			logger.info('Service %s is in stopped state'% service_name)
			
			# Let's check its configuration if service is stopped, maybe it's disabled :s
			ans = await scmr.hRQueryServiceConfigW(self.dce,self.handle)
			if ans['lpServiceConfig']['dwStartType'] == 0x4:
				logger.info('Service %s is disabled'% service_name)
				return SMBServiceStatus.DISABLED
			else:
				return SMBServiceStatus.STOPPED

		elif ans['lpServiceStatus']['dwCurrentState'] == scmr.SERVICE_RUNNING:
			logger.debug('Service %s is already running'% service_name)
			return SMBServiceStatus.RUNNING
		else:
			raise Exception('Unknown service state 0x%x - Aborting' % ans['CurrentState'])

	async def stop_service(self, service_name):
		raise NotImplementedError('stop_service')
	
	async def create_service(self, service_name, command):
		if not self.handle:
			await self.open()
		resp = await scmr.hRCreateServiceW(self.dce, self.handle, service_name, service_name, lpBinaryPathName=command)
		self.service_handles[service_name] = resp['lpServiceHandle']
		
	async def delete_service(self, service_name):
		if not self.handle:
			await self.open()
		if service_name not in self.service_handles:
			await self.open_service(service_name)
		
		await scmr.hRDeleteService(self.dce, self.service_handles[service_name])

	async def start_service(self, service_name):
		if not self.handle:
			await self.open()
		if service_name not in self.service_handles:
			await self.open_service(service_name)

			await scmr.hRStartServiceW(self.dce , self.service_handles[service_name])
			await asyncio.sleep(1) #service takes time to start up...
			
	async def enable_service(self, service_name):
		if not self.handle:
			await self.open()
		if service_name not in self.service_handles:
			await self.open_service(service_name)
			
		await scmr.hRChangeServiceConfigW(self.dce, self.service_handles[service_name])
