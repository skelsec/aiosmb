
import traceback

from aiosmb.dcerpc.v5.common.connection.authentication import DCERPCAuth
from aiosmb.dcerpc.v5.common.connection.target import DCERPCTarget
from aiosmb.connection import SMBConnection
from aiosmb.dcerpc.v5.connection import DCERPC5Connection
from aiosmb.dcerpc.v5 import icpr
from aiosmb.dcerpc.v5.interfaces.endpointmgr import EPM
from aiosmb.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_NONE, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, DCERPCException, RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_CONNECT

### This does not work over SMB, only TCP/IP!


class ICPRRPC:
	def __init__(self):
		self.service_pipename = None #not available via smb
		self.service_uuid = icpr.MSRPC_UUID_ICPR		
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
			service = ICPRRPC()
			service.dce = connection
			
			service.dce.set_auth_level(auth_level)
			if auth_level is None:
				service.dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY) #secure default :P
			
			_, err = await service.dce.connect()
			if err is not None:
				raise err
			
			_, err = await service.dce.bind(ICPRRPC().service_uuid)
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

			constring, err = await epm.map(ICPRRPC().service_uuid)
			if err is not None:
				raise err
			
			target = DCERPCTarget.from_connection_string(constring, smb_connection = connection)
			dcerpc_auth = DCERPCAuth.from_smb_gssapi(connection.gssapi)
			rpc_connection = DCERPC5Connection(dcerpc_auth, target)
			
			service, err = await ICPRRPC.from_rpcconnection(rpc_connection, auth_level=auth_level, open=open, perform_dummy = perform_dummy)	
			if err is not None:
				raise err

			return service, None
		except Exception as e:
			traceback.print_exc()
			return None, e
		finally:
			if epm is not None:
				await epm.disconnect()
	
	async def request_certificate(self, service, csr, attributes = {}, flags = 0, requestid = 1):
		try:
			flattrib = ""
			if len(attributes) > 0:
				flattrib = "\n".join(
					["{}:{}".format(k, attributes[k]) for k in attributes]
				)
			
			data, err = await icpr.hCertServerRequest(
				self.dce,
				service, 
				csr,
				dwFlags = flags, 
				pctbAttribs = flattrib, 
				pdwRequestId = requestid
			)
			if err is not None:
				raise err
			
			requestid = data['pdwRequestId']
			disposition = data['pdwDisposition']
			cert = b''.join(data['pctbCert']['pbData'])
			encodedcert = b''.join(data['pctbEncodedCert']['pbData'])
			disposition_message = b''.join(data['pctbDispositionMessage']['pbData']).decode('utf-16-le').replace('\x00', '')

			res = {
				'requestid' : requestid,
				'disposition' : disposition,
				'cert' : cert,
				'encodedcert' : encodedcert,
				'disposition_message' : disposition_message
			}
			
			return res, None
		
		except Exception as e:
			return None, e

