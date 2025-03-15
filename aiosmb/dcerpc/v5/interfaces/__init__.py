from aiosmb.dcerpc.v5.common.connection.smbdcefactory import SMBDCEFactory
from aiosmb import logger
from aiosmb.dcerpc.v5.dtypes import NULL
from aiosmb.dcerpc.v5.interfaces.endpointmgr import EPM
from aiosmb.dcerpc.v5.common.connection.authentication import DCERPCAuth
from aiosmb.dcerpc.v5.common.connection.target import DCERPCTarget
from aiosmb.connection import SMBConnection
from aiosmb.dcerpc.v5.connection import DCERPC5Connection
from aiosmb.dcerpc.v5.uuid import uuidtup_to_bin
from aiosmb.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_NONE,\
	RPC_C_AUTHN_LEVEL_CONNECT,\
	RPC_C_AUTHN_LEVEL_CALL,\
	RPC_C_AUTHN_LEVEL_PKT,\
	RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,\
	RPC_C_AUTHN_LEVEL_PKT_PRIVACY,\
	DCERPCException, RPC_C_AUTHN_GSS_NEGOTIATE

from abc import ABC, abstractmethod

class InterfaceEndpoint:
	def __init__(self, etype, uuid, version, pipename = None, authlevel=RPC_C_AUTHN_LEVEL_NONE):
		self.etype = etype.lower()
		self.uuid = uuid
		self.version = version
		self.pipename = pipename
		self.authlevel = authlevel
		self._smb_connection_to_close = None

		if self.etype == 'ncan_np' and self.pipename is None:
			raise ValueError('pipename must be specified for ncan_np endpoint type')

	def service_uuid(self):
		return uuidtup_to_bin((self.uuid, self.version))
	
	def __str__(self):
		return '(%s,%s,%s)' % (self.etype, self.uuid, self.version)

class InterfaceManager(ABC):
	def __init__(self, connection, endpoint):
		self.dce = connection
		self.endpoint = endpoint

	async def __aenter__(self):
		return self
	
	async def __aexit__(self, exc_type, exc, traceback):
		await self.close()
	
	async def close(self):
		try:
			try:
				await self.cleanup()
			except:
				pass
			await self.dce.disconnect()
			if self._smb_connection_to_close is not None:
				await self._smb_connection_to_close.disconnect()
			
			return True, None
		except Exception as e:
			return None, e
	
	# Abstract methods for child classes to define their own UUID and pipename
	@classmethod
	@abstractmethod
	def endpoints(cls):
		raise NotImplementedError("Must be implemented in the child class")
	
	@abstractmethod
	async def cleanup(cls):
		"""Called when the object is destroyed"""
		"""Implement this in the child class when handles need to be closed"""
		pass
	
	@staticmethod
	def create_instance(connection, endpoint):
		raise NotImplementedError("Must be implemented in the child class")

	async def connect(self):
		try:
			_, err = await self.dce.connect()
			if err is not None:
				raise err
			
			_, err = await self.dce.bind(self.endpoint.service_uuid())
			if err is not None:
				raise err
			
			return True, None
		except Exception as e:
			return False, e
	
	@classmethod
	async def from_rpcconnection(cls, connection:DCERPC5Connection, endpoint:InterfaceEndpoint=None, connect:bool=True, smb_connection_to_close=None):
		try:
			if endpoint is None:
				endpoint = cls.endpoints()[0]
			
			service = cls.create_instance(connection, endpoint)  # Create instance of the child class
			service.dce.set_auth_level(endpoint.authlevel)
			service._smb_connection_to_close = smb_connection_to_close

			if connect is True:
				_, err = await service.connect()
				if err is not None:
					raise err
			
			return service, None
		except Exception as e:
			return False, e
	
	@classmethod
	async def switch_protocol(cls, connection:SMBConnection, endpoint:InterfaceEndpoint):
		try:
			epm = EPM.from_address(connection.target.get_hostname_or_ip(), proxies=connection.target.proxies)
			_, err = await epm.connect()
			if err is not None:
				raise err

			async with epm:
				constring, err = await epm.map(endpoint.service_uuid())
				if err is not None:
					raise err
				
			target = DCERPCTarget.from_connection_string(
				constring,
				hostname= connection.target.get_hostname_or_ip(), 
				proxies = connection.target.proxies,
				dc_ip = connection.target.dc_ip,
				domain = connection.target.domain
			)

			dcerpc_auth = DCERPCAuth.from_smb_gssapi(connection.gssapi)
			rpc_connection = DCERPC5Connection(dcerpc_auth, target)
			return rpc_connection, None
		except Exception as e:
			return None, e
	
	@classmethod
	async def from_smbconnection(cls, connection:SMBConnection, endpoint:InterfaceEndpoint = None, connect:bool=True):
		try:
			smb_connection_to_close = None
			if endpoint is None:
				endpoint = cls.endpoints()[0]

			if endpoint.etype != 'ncan_np':
				# switch protocol
				rpctransport, err = await cls.switch_protocol(connection, endpoint)
				if err is not None:
					raise err
			else:
				if connection.login_ok is False:
					# Be careful with this, as it will try to login with the current credentials
					# If this code part runs, the smb connection WILL be cleaned up when the interface is destroyed
					_, err = await connection.login()
					if err is not None:
						raise err
					smb_connection_to_close = connection
					
				rpctransport_factory = SMBDCEFactory(connection, filename=endpoint.pipename)
				rpctransport = rpctransport_factory.get_dce_rpc()
			
			service, err = await cls.from_rpcconnection(
				rpctransport, 
				endpoint = endpoint,
				connect=connect,
				smb_connection_to_close=smb_connection_to_close
			)
			if err is not None:
				raise err

			return service, None
		except Exception as e:
			return None, e
	
	@classmethod
	def get_endpoint(cls, etype):
		etype = etype.lower()
		for ep in cls.endpoints():
			if ep.etype == etype:
				return ep
		return None

	@classmethod
	async def from_ntlm_params(cls, target, username, password, domain, endpoint:InterfaceEndpoint = None, endpoint_type:str=None, connect:bool=True, proxies=None):
		try:
			if endpoint is None:
				if endpoint_type is None:
					endpoint = cls.endpoints()[0]
				else:
					endpoint = cls.get_endpoint(endpoint_type)
			
			if endpoint.etype == 'ncan_np':
				from aiosmb.commons.connection.factory import SMBConnectionFactory

				factory = SMBConnectionFactory.from_components(
					ip_or_hostname=target,
					username=username, 
					secret=password,
					domain=domain,
					secrettype='password',
					proxies=proxies,
					dialect='smb3',
				)

				connection = factory.get_connection()
				_, err = await connection.login()
				if err is not None:
					raise err
				
				service, err = await cls.from_smbconnection(connection, endpoint=endpoint, connect=connect)
				if err is not None:
					raise err
				return service, None
			else:
				from aiosmb.dcerpc.v5.interfaces.endpointmgr import EPM
				from aiosmb.dcerpc.v5.common.connection.authentication import DCERPCAuth
				from aiosmb.dcerpc.v5.common.connection.target import DCERPCTarget

				epm = EPM.from_address(target, proxies=proxies)
				_, err = await epm.connect()
				if err is not None:
					raise err

				async with epm:
					constring, err = await epm.map(endpoint.service_uuid())
					if err is not None:
						raise err
				
				target = DCERPCTarget.from_connection_string(
					constring,
					hostname=target, 
					proxies = proxies,
					dc_ip = None,
					domain = None
				)
				dcerpc_auth = DCERPCAuth.from_components(
					username = username, 
					secret=password, 
					secrettype='password',
					domain = domain, 
					authproto= 'ntlm'
				)
				rpc_connection = DCERPC5Connection(dcerpc_auth, target)
				service, err = await cls.from_rpcconnection(rpc_connection, endpoint=endpoint, connect=connect)
				if err is not None:
					raise err
				return service, None

		except Exception as e:
			return None, e