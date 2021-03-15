import enum
import asyncio

from aiosmb import logger
from aiosmb.dcerpc.v5.common.service import SMBServiceStatus, SMBService
from aiosmb.dcerpc.v5.common.connection.smbdcefactory import SMBDCEFactory
from aiosmb.dcerpc.v5 import wkst, scmr

from aiosmb.commons.utils.decorators import red, red_gen

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
		return True,None
	
	@red
	async def connect(self, open = True):
		rpctransport = SMBDCEFactory(self.connection, filename=r'\svcctl')
		self.dce = rpctransport.get_dce_rpc()
		_, err = await self.dce.connect()
		if err is not None:
			return False, err
		_, err = await self.dce.bind(scmr.MSRPC_UUID_SCMR)
		if err is not None:
			return False, err

		if open == True:
			_, err = await self.open()
			if err is not None:
				return False, err
		
		return True,None
	
	@red
	async def open(self):
		if not self.dce:
			_, err = await self.connect()
			if err is not None:
				return False, err
		
		ans, err = await scmr.hROpenSCManagerW(self.dce)
		if err is not None:
			return False, err
		
		self.handle = ans['lpScHandle']

		return True,None
	
	@red
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
		
		return True,None

	@red_gen
	async def list(self):
		resp, err = await scmr.hREnumServicesStatusW(self.dce, self.handle)
		if err is not None:
			yield None, err
			return
		
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
			yield service, None
	
	@red
	async def open_service(self, service_name, desired_access = scmr.SERVICE_ALL_ACCESS):
		if service_name in self.service_handles:
			return False, None
			
		ans, err = await scmr.hROpenServiceW(self.dce, self.handle, service_name, dwDesiredAccess = desired_access)
		if err is not None:
			return None, err

		self.service_handles[service_name] = ans['lpServiceHandle']

		return True,None
	
	@red
	async def close_service(self, service_name):
		if not self.handle:
			_, err = await self.open()
			if err is not None:
				return None, err
		if service_name not in self.service_handles:
			_, err = await self.open_service(service_name)
			if err is not None:
				return None, err
		
		_, err = await scmr.hRCloseServiceHandle(self.dce, self.service_handles[service_name])
		if err is not None:
			return None, err
		
		del self.service_handles[service_name]

		return True, None
	
	@red
	async def check_service_status(self, service_name):
		if not self.handle:
			_, err = await self.open()
			if err is not None:
				raise err

		if service_name not in self.service_handles:
			_, err = await self.open_service(service_name)
			if err is not None:
				raise err
		
		ans, err = await scmr.hRQueryServiceStatus(self.dce, self.service_handles[service_name])
		if err is not None:
			raise err
		
		if ans['lpServiceStatus']['dwCurrentState'] == scmr.SERVICE_STOPPED:
			logger.info('Service %s is in stopped state'% service_name)
			
			# Let's check its configuration if service is stopped, maybe it's disabled :s
			ans, err = await scmr.hRQueryServiceConfigW(self.dce, self.service_handles[service_name])
			if ans['lpServiceConfig']['dwStartType'] == 0x4:
				logger.info('Service %s is disabled'% service_name)
				return SMBServiceStatus.DISABLED, None
			else:
				return SMBServiceStatus.STOPPED, None

		elif ans['lpServiceStatus']['dwCurrentState'] == scmr.SERVICE_RUNNING:
			logger.debug('Service %s is already running'% service_name)
			return SMBServiceStatus.RUNNING, None
		else:
			raise Exception('Unknown service state 0x%x - Aborting' % ans['CurrentState'])

		return False, None
	
	@red
	async def stop_service(self, service_name):
		return await self.change_service_status(service_name, scmr.SERVICE_CONTROL_STOP)


	@red
	async def change_service_status(self, service_name, service_status):
		if not self.handle:
			_, err = await self.open()
			if err is not None:
				return None, err

		if service_name not in self.service_handles:
			desired_access = scmr.SERVICE_ALL_ACCESS
			if service_status == scmr.SERVICE_CONTROL_STOP:
				desired_access = scmr.SERVICE_STOP
			_, err = await self.open_service(service_name, desired_access)
			if err is not None:
				return None, err
		
		_, err = await scmr.hRControlService(self.dce, self.handle, service_status)
		if err is not None:
			return False, err
		
		return True, None
	
	@red
	async def create_service(self, service_name, display_name, command):
		if not self.handle:
			_, err = await self.open()
			if err is not None:
				return None, err

		resp, err = await scmr.hRCreateServiceW(self.dce, self.handle, service_name + '\x00', display_name + '\x00', lpBinaryPathName=command + '\x00')
		if err is not None:
			return None, err
		self.service_handles[service_name] = resp['lpServiceHandle']
		return resp, err
	
	@red
	async def delete_service(self, service_name):
		if not self.handle:
			_, err = await self.open()
			if err is not None:
				return None, err

		if service_name not in self.service_handles:
			_, err = await self.open_service(service_name)
			if err is not None:
				return None, err
		
		_, err = await scmr.hRDeleteService(self.dce, self.service_handles[service_name])
		if err is not None:
			return None, err
		return True,None
	
	@red
	async def start_service(self, service_name):
		if not self.handle:
			_, err = await self.open()
			if err is not None:
				return None, err

		if service_name not in self.service_handles:
			_, err = await self.open_service(service_name)
			if err is not None:
				return None, err

		_, err = await scmr.hRStartServiceW(self.dce , self.service_handles[service_name])
		if err is not None:
			return None, err
			
		await asyncio.sleep(1) #service takes time to start up...
		return True,None
	
	@red
	async def enable_service(self, service_name):
		if not self.handle:
			_, err = await self.open()
			if err is not None:
				return None, err

		if service_name not in self.service_handles:
			_, err = await self.open_service(service_name)
			if err is not None:
				return None, err
			
		_, err = await scmr.hRChangeServiceConfigW(self.dce, self.service_handles[service_name], dwStartType=scmr.SERVICE_AUTO_START)
		if err is not None:
			return None, err

		return True,None
