from aiosmb.dcerpc.v5.common.connection.smbdcefactory import SMBDCEFactory
from aiosmb.connection import SMBConnection
from aiosmb.dcerpc.v5.connection import DCERPC5Connection
from aiosmb.dcerpc.v5 import srvs
from aiosmb.wintypes.ntstatus import NTStatus
from aiosmb import logger
from aiosmb.dcerpc.v5.dtypes import NULL
from aiosmb.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_NONE,\
	RPC_C_AUTHN_LEVEL_CONNECT,\
	RPC_C_AUTHN_LEVEL_CALL,\
	RPC_C_AUTHN_LEVEL_PKT,\
	RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,\
	RPC_C_AUTHN_LEVEL_PKT_PRIVACY,\
	DCERPCException, RPC_C_AUTHN_GSS_NEGOTIATE

from contextlib import asynccontextmanager

@asynccontextmanager
async def srvsrpc_from_smb(connection, auth_level=None, open=True, perform_dummy=False):
    instance, err = await SRVSRPC.from_smbconnection(connection, auth_level=auth_level, open=open, perform_dummy=perform_dummy)
    if err:
        # Handle or raise the error as appropriate
        raise err
    try:
        yield instance
    finally:
        await instance.close()
		
class SRVSRPC:
	def __init__(self):
		self.service_pipename = r'\srvsvc'
		self.service_uuid = srvs.MSRPC_UUID_SRVS
		self.service_manager = None
		
		self.dce = None
		self.handle = None
		
		self.domain_ids = {} #sid to RPC_SID
		self.domain_handles = {} #handle to sid
		
	async def __aenter__(self):
		return self
		
	async def __aexit__(self, exc_type, exc, traceback):
		await self.close()
		return True,None
	
	@staticmethod
	async def from_rpcconnection(connection:DCERPC5Connection, auth_level = None, open:bool = True, perform_dummy:bool = False):
		try:
			service = SRVSRPC()
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
			rpctransport = SMBDCEFactory(connection, filename=SRVSRPC().service_pipename)		
			service, err = await SRVSRPC.from_rpcconnection(rpctransport.get_dce_rpc(), auth_level=auth_level, open=open, perform_dummy = perform_dummy)	
			if err is not None:
				raise err

			return service, None
		except Exception as e:
			return None, e
	

	async def close(self):
		try:
			if self.dce:
				try:
					await self.dce.disconnect()
				except:
					pass
				return
			
			return True,None
		except Exception as e:
			return None, e
	
	async def list_shares(self, level = 1):
		try:
			level_name = 'Level%s' % level
			status = NTStatus.MORE_ENTRIES
			resumeHandle = 0
			while status == NTStatus.MORE_ENTRIES:
				resp, err = await srvs.hNetrShareEnum(self.dce, level, resumeHandle = resumeHandle)
				if err is not None:
					if err.error_code != NTStatus.MORE_ENTRIES.value:
						raise err
					resp = err.get_packet()

				for entry in resp['InfoStruct']['ShareInfo'][level_name]['Buffer']:
					yield entry['shi1_netname'][:-1], entry['shi1_type'], entry['shi1_remark'], None
				
				resumeHandle = resp['ResumeHandle'] 
				status = NTStatus(resp['ErrorCode'])
		except Exception as e:
			yield None,None,None, e
			return
	
	async def list_sessions(self, level = 10):
		try:
			if level not in [1, 10]:
				raise Exception('Only levels 1 and 10 implemented!')
			level_name = 'Level%s' % level
			status = NTStatus.MORE_ENTRIES
			resumeHandle = 0
			while status == NTStatus.MORE_ENTRIES:
				resp, err = await srvs.hNetrSessionEnum(self.dce, '\x00', NULL, level, resumeHandle = resumeHandle)
				if err is not None:
					if err.error_code != NTStatus.MORE_ENTRIES.value:
						yield None, None, err
						return
					resp = err.get_packet()

				if level == 1:
					for entry in resp['InfoStruct']['SessionInfo'][level_name]['Buffer']:
						username = entry['sesi1_username'][:-1]
						ip_addr = entry['sesi1_cname'][:-1]					
						yield username, ip_addr, None

				elif level == 10:
					for entry in resp['InfoStruct']['SessionInfo'][level_name]['Buffer']:
						username = entry['sesi10_username'][:-1]
						ip_addr = entry['sesi10_cname'][:-1]
						
						yield username, ip_addr, None
				
				resumeHandle = resp['ResumeHandle'] 
				status = NTStatus(resp['ErrorCode'])
		except Exception as e:
			yield None, None, e
			return