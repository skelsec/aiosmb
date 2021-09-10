
import asyncio
import os
import io

from aiosmb.dcerpc.v5.common.connection.authentication import DCERPCAuth
from aiosmb.dcerpc.v5.common.connection.target import DCERPCTarget
from aiosmb.connection import SMBConnection
from aiosmb.dcerpc.v5.connection import DCERPC5Connection
from aiosmb.dcerpc.v5 import even6
from aiosmb.dcerpc.v5.interfaces.endpointmgr import EPM
from aiosmb.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_NONE, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, DCERPCException, RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_CONNECT
from aiosmb.dcerpc.v5.common.even6.binxml import Fragment
from aiosmb.dcerpc.v5.common.even6.resultset import RESULT_SET

### This does not work over SMB, only TCP/IP! Also, the RPC_C_AUTHN_LEVEL_PKT_PRIVACY must be set!!!
### 
###
###

class Even6RPC:
	def __init__(self):
		self.service_pipename = None #not available via smb
		self.service_uuid = even6.MSRPC_UUID_EVEN6
		self.handles = {}
		
		self.dce = None
		
	async def __aenter__(self):
		return self
		
	async def __aexit__(self, exc_type, exc, traceback):
		await self.close()
		return True,None
	
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
	
	@staticmethod
	async def from_rpcconnection(connection:DCERPC5Connection, auth_level = None, open:bool = True, perform_dummy:bool = False):
		try:
			service = Even6RPC()
			service.dce = connection
			
			service.dce.set_auth_level(auth_level)
			if auth_level is None:
				service.dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY) #secure default :P
			
			_, err = await service.dce.connect()
			if err is not None:
				raise err
			
			_, err = await service.dce.bind(Even6RPC().service_uuid)
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
				auth_level = RPC_C_AUTHN_LEVEL_PKT_PRIVACY
			
			epm = EPM.from_smbconnection(connection)
			_, err = await epm.connect()
			if err is not None:
				raise err

			constring, err = await epm.map(Even6RPC().service_uuid)
			if err is not None:
				raise err
			
			target = DCERPCTarget.from_connection_string(constring, smb_connection = connection)
			dcerpc_auth = DCERPCAuth.from_smb_gssapi(connection.gssapi)
			rpc_connection = DCERPC5Connection(dcerpc_auth, target)
			
			service, err = await Even6RPC.from_rpcconnection(rpc_connection, auth_level=auth_level, open=open, perform_dummy = perform_dummy)	
			if err is not None:
				raise err

			return service, None
		except Exception as e:
			return None, e
		finally:
			if epm is not None:
				await epm.disconnect()
	
	async def register_query(self, path, query = '*', flags = even6.EvtQueryChannelName | even6.EvtReadNewestToOldest):
		try:
			if path[-1] != '\x00':
				path += '\x00'
			if query[-1] != '\x00':
				query += '\x00'
			res, err = await even6.hEvtRpcRegisterLogQuery(self.dce, path, flags, query = query)
			if err is not None:
				raise err
			
			return res['Handle'], None
		
		except Exception as e:
			return None, e

	async def query_next(self, handle, num_req, timeout = 1000, as_xml = False):
		try:
			onetime = 10
			ranges = []
			if num_req <= onetime:
				ranges.append(num_req)
			else:
				i = 0
				while True:
					ranges.append(onetime)
					i += onetime
					if (i + onetime) < num_req:
						continue
					elif i == num_req:
						break
					else:
						ranges.append(num_req-i)
						break

			for i in ranges:
				res, err = await even6.hEvtRpcQueryNext(self.dce, handle, i, timeOutEnd=timeout)
				if err is not None:
					raise err
				
				pos = [x['Data'] for x in res['EventDataIndices']]
				size = [x['Data']for x in res['EventDataSizes']]
				buff = io.BytesIO(b''.join(res['ResultBuffer']))
				
				for p,s in zip(pos, size):
					buff.seek(p,io.SEEK_SET)
					if as_xml is False:
						yield RESULT_SET.from_bytes(buff.read(s)), None
					else:
						yield Fragment.from_bytes(RESULT_SET.from_bytes(buff.read(s)).eventData).to_xml() , None
			
		except Exception as e:
			yield None, e
			return

	async def list_channels(self):
		try:
			# doesnt work!
			res, err = await even6.hEvtRpcGetChannelList(self.dce)
			if err is not None:
				raise err

			return [x['Data'].replace('\x00','') for x in res['ChannelPaths']], None

		except Exception as e:
			return None, e

