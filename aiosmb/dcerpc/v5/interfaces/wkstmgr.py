from aiosmb.dcerpc.v5.common.connection.smbdcefactory import SMBDCEFactory
from aiosmb.dcerpc.v5 import wkst
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
async def wkstrpc_from_smb(connection, auth_level=None, open=True, perform_dummy=False):
    instance, err = await WKSTRPC.from_smbconnection(connection, auth_level=auth_level, open=open, perform_dummy=perform_dummy)
    if err:
        # Handle or raise the error as appropriate
        raise err
    try:
        yield instance
    finally:
        await instance.close()
		
class WKSTRPC:
	def __init__(self):
		self.service_pipename = r'\wkssvc'
		self.service_uuid = wkst.MSRPC_UUID_WKST
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
			service = WKSTRPC()
			service.dce = connection
			
			#service.dce.set_auth_level(auth_level)
			#if auth_level is None:
			#	service.dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY) #secure default :P
			
			_, err = await service.dce.connect()
			if err is not None:
				raise err
			
			_, err = await service.dce.bind(WKSTRPC().service_uuid)
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
			rpctransport = SMBDCEFactory(connection, filename=WKSTRPC().service_pipename)		
			service, err = await WKSTRPC.from_rpcconnection(rpctransport.get_dce_rpc(), auth_level=auth_level, open=open, perform_dummy = perform_dummy)	
			if err is not None:
				raise err

			return service, None
		except Exception as e:
			return None, e
	
	async def list_sessions(self, level=0):
		try:
			if level not in [0,1]:
				raise Exception('Level must be 0 or 1!')
			resp, err = await wkst.hNetrWkstaUserEnum(self.dce, level, preferredMaximumLength=0xffffffff)
			if err is not None:
				raise err
			
			if level == 0:
				for session in resp['UserInfo']['WkstaUserInfo']['Level0']['Buffer']:
					username = session['wkui0_username'][:-1]
					yield username, '', None

			elif level == 1:
				for session in resp['UserInfo']['WkstaUserInfo']['Level1']['Buffer']:
					username = session['wkui1_username'][:-1]
					domain = session['wkui1_logon_domain'][:-1]
					#session['wkui1_logon_server'][:-1]
					#session['wkui1_oth_domains'][:-1]
					yield '%s\\%s' % (domain, username), '', None

		except Exception as e:
			yield None, None, e