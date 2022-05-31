import enum
import asyncio
from inspect import trace
import traceback

from aiosmb import logger
from aiosmb.dcerpc.v5.common.service import SMBServiceStatus, SMBService
from aiosmb.dcerpc.v5.common.connection.smbdcefactory import SMBDCEFactory
from aiosmb.connection import SMBConnection
from aiosmb.dcerpc.v5.connection import DCERPC5Connection
from aiosmb.dcerpc.v5 import scmr
from aiosmb.dcerpc.v5.interfaces.endpointmgr import EPM
from aiosmb.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_NONE,\
	RPC_C_AUTHN_LEVEL_CONNECT,\
	RPC_C_AUTHN_LEVEL_CALL,\
	RPC_C_AUTHN_LEVEL_PKT,\
	RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,\
	RPC_C_AUTHN_LEVEL_PKT_PRIVACY,\
	DCERPCException, RPC_C_AUTHN_GSS_NEGOTIATE

from aiosmb.commons.utils.decorators import red, red_gen

class REMSVCRPC:
	def __init__(self):
		self.service_pipename = r'\svcctl'
		self.service_uuid = scmr.MSRPC_UUID_SCMR
		self.dce = None
		self.handle = None
		
		self.service_handles = {} #service_name -> handle
		
	async def __aenter__(self):
		return self
		
	async def __aexit__(self, exc_type, exc, traceback):
		await self.close()
		return True,None
	
	@staticmethod
	async def from_rpcconnection(connection:DCERPC5Connection, auth_level = None, open:bool = True, perform_dummy:bool = False):
		try:
			service = REMSVCRPC()
			service.dce = connection
			
			service.dce.set_auth_level(auth_level)
			if auth_level is None:
				service.dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY) #secure default :P 
			
			_, err = await service.dce.connect()
			if err is not None:
				raise err
			
			_, err = await service.dce.bind(service.service_uuid)
			if err is not None:
				raise err
			
			if open is True:
				_, err = await service.open()
				if err is not None:
					raise err
				
			return service, None
		except Exception as e:
			return False, e
	
	@staticmethod
	async def from_smbconnection(connection:SMBConnection, auth_level = None, open:bool = True, perform_dummy:bool = False):
		"""
		Creates the connection to the service using an established SMBConnection.
		This connection will use the given SMBConnection as transport layer.
		"""
		try:
			if auth_level is None:
				#for SMB connection no extra auth needed
				auth_level = RPC_C_AUTHN_LEVEL_NONE
			rpctransport = SMBDCEFactory(connection, filename=REMSVCRPC().service_pipename)		
			service, err = await REMSVCRPC.from_rpcconnection(rpctransport.get_dce_rpc(), auth_level=auth_level, open=open, perform_dummy = perform_dummy)	
			if err is not None:
				raise err

			return service, None
		except Exception as e:
			return None, e
	
	async def open(self):
		try:			
			ans, err = await scmr.hROpenSCManagerW(self.dce)
			if err is not None:
				return False, err
			
			self.handle = ans['lpScHandle']

			return True,None
		except Exception as e:
			return None, e
	
	async def close(self):
		try:
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
		except Exception as e:
			return None, e

	async def list(self):
		try:
			resp, err = await scmr.hREnumServicesStatusW(self.dce, self.handle)
			if err is not None:
				raise err
			
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
		except Exception as e:
			yield None, e
	
	async def open_service(self, service_name, desired_access = scmr.SERVICE_ALL_ACCESS):
		try:
			if service_name in self.service_handles:
				return False, None
				
			ans, err = await scmr.hROpenServiceW(self.dce, self.handle, service_name, dwDesiredAccess = desired_access)
			if err is not None:
				raise err

			self.service_handles[service_name] = ans['lpServiceHandle']

			return True,None
		except Exception as e:
			return None, e
	
	async def close_service(self, service_name):
		try:
			if not self.handle:
				_, err = await self.open()
				if err is not None:
					raise err
			if service_name not in self.service_handles:
				_, err = await self.open_service(service_name)
				if err is not None:
					raise err
			
			_, err = await scmr.hRCloseServiceHandle(self.dce, self.service_handles[service_name])
			if err is not None:
				raise err
			
			del self.service_handles[service_name]

			return True, None
		except Exception as e:
			return None, e
	
	async def check_service_status(self, service_name):
		try:
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
				if err is not None:
					raise err
				if ans['lpServiceConfig']['dwStartType'] == 0x4:
					return SMBServiceStatus.DISABLED, None
				else:
					return SMBServiceStatus.STOPPED, None

			elif ans['lpServiceStatus']['dwCurrentState'] == scmr.SERVICE_RUNNING:
				logger.debug('Service %s is already running'% service_name)
				return SMBServiceStatus.RUNNING, None
			else:
				raise Exception('Unknown service state 0x%x - Aborting' % ans['CurrentState'])
		except Exception as e:
			return None, e
	
	async def stop_service(self, service_name):
		try:
			_, err = await self.change_service_status(service_name, scmr.SERVICE_CONTROL_STOP)
			if err is not None:
				raise err
			return True, None
		except Exception as e:
			return None, e

	async def change_service_status(self, service_name, service_status):
		try:
			if not self.handle:
				_, err = await self.open()
				if err is not None:
					raise err

			if service_name not in self.service_handles:
				desired_access = scmr.SERVICE_ALL_ACCESS
				if service_status == scmr.SERVICE_CONTROL_STOP:
					desired_access = scmr.SERVICE_STOP
				_, err = await self.open_service(service_name, desired_access)
				if err is not None:
					raise err
			
			_, err = await scmr.hRControlService(self.dce, self.handle, service_status)
			if err is not None:
				raise err
			
			return True, None
		except Exception as e:
			return None, e
	
	async def create_service(self, service_name, display_name, command, starttype = scmr.SERVICE_AUTO_START):
		try:
			if not self.handle:
				_, err = await self.open()
				if err is not None:
					raise err

			resp, err = await scmr.hRCreateServiceW(self.dce, self.handle, service_name + '\x00', display_name + '\x00', lpBinaryPathName=command + '\x00', dwStartType=starttype)
			if err is not None:
				raise err
			self.service_handles[service_name] = resp['lpServiceHandle']
			return resp, err
		except Exception as e:
			return None, e
	
	async def delete_service(self, service_name):
		try:
			if not self.handle:
				_, err = await self.open()
				if err is not None:
					raise err

			if service_name not in self.service_handles:
				_, err = await self.open_service(service_name)
				if err is not None:
					raise err
			
			_, err = await scmr.hRDeleteService(self.dce, self.service_handles[service_name])
			if err is not None:
				raise err
			return True, None
		except Exception as e:
			return None, e
	

	async def start_service(self, service_name):
		try:
			if not self.handle:
				_, err = await self.open()
				if err is not None:
					raise err

			if service_name not in self.service_handles:
				_, err = await self.open_service(service_name)
				if err is not None:
					raise err

			_, err = await scmr.hRStartServiceW(self.dce, self.service_handles[service_name])
			if err is not None:
				raise err
				
			await asyncio.sleep(1) #service takes time to start up...
			return True,None
		except Exception as e:
			return None, e
	
	async def enable_service(self, service_name):
		try:
			if not self.handle:
				_, err = await self.open()
				if err is not None:
					raise err

			if service_name not in self.service_handles:
				_, err = await self.open_service(service_name)
				if err is not None:
					raise err
				
			_, err = await scmr.hRChangeServiceConfigW(self.dce, self.service_handles[service_name], dwStartType=scmr.SERVICE_AUTO_START)
			if err is not None:
				raise err

			return True,None
		except Exception as e:
			return None, e
