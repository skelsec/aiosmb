from aiosmb.dcerpc.v5.common.connection.smbdcefactory import SMBDCEFactory
from aiosmb.dcerpc.v5 import atsvc
from aiosmb.dcerpc.v5.interfaces.endpointmgr import EPM
from aiosmb.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
from aiosmb.wintypes.ntstatus import NTStatus
from aiosmb import logger
from aiosmb.dcerpc.v5.dtypes import NULL
from aiosmb.dcerpc.v5.interfaces.endpointmgr import EPM
from aiosmb.connection import SMBConnection
from aiosmb.dcerpc.v5.connection import DCERPC5Connection
from aiosmb.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_NONE,\
	RPC_C_AUTHN_LEVEL_CONNECT,\
	RPC_C_AUTHN_LEVEL_CALL,\
	RPC_C_AUTHN_LEVEL_PKT,\
	RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,\
	RPC_C_AUTHN_LEVEL_PKT_PRIVACY,\
	DCERPCException, RPC_C_AUTHN_GSS_NEGOTIATE

from contextlib import asynccontextmanager

@asynccontextmanager
async def atsvcrpc_from_smb(connection, auth_level=None, open=True, perform_dummy=False):
	instance, err = await ATSVCRPC.from_smbconnection(connection, auth_level=auth_level, open=open, perform_dummy=perform_dummy)
	if err:
		# Handle or raise the error as appropriate
		raise err
	try:
		yield instance
	finally:
		await instance.close()
		
class ATSVCRPC:
	def __init__(self):
		self.service_pipename = r'\atsvc'
		self.service_uuid = atsvc.MSRPC_UUID_ATSVC
		self.dce = None
		self.handle = None
		
		#self.policy_handles = {} #handle to sid
		#self.ph_ctr = 0
		
	async def __aenter__(self):
		return self
	
	async def __aexit__(self, exc_type, exc, traceback):
		await self.close()
		return True, None
	
	async def close(self):		
		try:
			if self.dce:
				try:
					await self.dce.disconnect()
				except:
					pass
				return True, None
		except Exception as e:
			return None, e
	
	@staticmethod
	async def from_rpcconnection(connection:DCERPC5Connection, auth_level = None, open:bool = True, perform_dummy:bool = False):
		try:
			service = ATSVCRPC()
			service.dce = connection
			
			#service.dce.set_auth_level(auth_level)
			#if auth_level is None:
			#	service.dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY) #secure default :P
			
			_, err = await service.dce.connect()
			if err is not None:
				raise err
			
			_, err = await service.dce.bind(ATSVCRPC().service_uuid)
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
			rpctransport = SMBDCEFactory(connection, filename=ATSVCRPC().service_pipename)		
			service, err = await ATSVCRPC.from_rpcconnection(rpctransport.get_dce_rpc(), auth_level=auth_level, open=open, perform_dummy = perform_dummy)	
			if err is not None:
				raise err

			return service, None
		except Exception as e:
			return None, e
	
	async def add_job(self, atinfo, servername = None):
		try:
			if servername is None:
				servername = NULL
			ans, err = await atsvc.hNetrJobAdd(self.dce, servername, atinfo)
			if err is not None:
				raise err
			return ans['JobId'], None

		except Exception as e:
			return None, e
	
	async def del_job(self, jobid, servername = None):
		try:
			if servername is None:
				servername = NULL
			_, err = await atsvc.hNetrJobDel(self.dce, servername, jobid)
			if err is not None:
				raise err
			return True, None

		except Exception as e:
			return None, e
	
	async def enum_jobs(self, servername = None):
		try:
			if servername is None:
				servername = NULL
			ans, err = await atsvc.hNetrJobEnum(self.dce, servername)
			if err is not None:
				raise err
			ans.dump()
			return ans['JobEntries'], None

		except Exception as e:
			return None, e
	
	async def get_job(self, jobid, servername = None):
		try:
			if servername is None:
				servername = NULL
			ans, err = await atsvc.hNetrJobGetInfo(self.dce, servername, jobid)
			if err is not None:
				raise err
			return ans['ppAtInfo'], None

		except Exception as e:
			return None, e