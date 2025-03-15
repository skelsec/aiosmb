import traceback
from typing import List
from aiosmb.dcerpc.v5.epm import *
from aiosmb.dcerpc.v5.connection import DCERPC5Connection
from aiosmb.dcerpc.v5.common.connection.target import DCERPCTarget
from aiosmb.dcerpc.v5.common.connection.authentication import DCERPCAuth
from aiosmb.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_NONE,\
	RPC_C_AUTHN_LEVEL_CONNECT,\
	RPC_C_AUTHN_LEVEL_CALL,\
	RPC_C_AUTHN_LEVEL_PKT,\
	RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,\
	RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from asysocks.unicomm.common.proxy import UniProxyTarget
from asysocks.unicomm.common.target import UniTarget

from asyauth.common.credentials.spnego import SPNEGOCredential
from asyauth.common.credentials.ntlm import NTLMCredential
from asyauth.common.credentials.kerberos import KerberosCredential

"""
EPM is a bit special interface, as it seems it doesn't require authentication?
So it should have been easy to just create a static method to resolv endpoints.
However there is a bit of a problem whan you want to use it with proxyies,
hence an interface needed to be created that takes the proxy settings into account
"""
class EPM:
	def __init__(self, connection:DCERPC5Connection, data_representation:bytes = None):
		self.dce = connection
		self.data_representation = data_representation
		if data_representation is None:
			self.data_representation = uuidtup_to_bin(('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0'))
	
	async def __aenter__(self):
		return self
	
	async def __aexit__(self, exc_type, exc, traceback):
		await self.disconnect()

	@staticmethod
	def from_address(ip, port:int = 135, protocol:str = 'ncacn_ip_tcp', data_representation = None, proxies:List[UniProxyTarget] = None):
		"""
		Sets up the EPM object from IP/hostname port protocol parameters
		"""
		dcerpc_target_str = r'%s:%s[%s]' % (protocol, ip, port)
		target = DCERPCTarget.from_connection_string(
			dcerpc_target_str, 
			proxies = proxies
		)
		auth = None
		connection = DCERPC5Connection(auth, target)
		connection.set_auth_type(RPC_C_AUTHN_LEVEL_NONE)
		return EPM(connection, data_representation)

	@staticmethod
	def from_smbconnection(smb_connection, port:int = 135, protocol:str = 'ncacn_ip_tcp', data_representation = None):
		"""
		Sets up the EPM connection from an existing SMB connection
		"""
		dcerpc_target_str = r'%s:%s[%s]' % (protocol, smb_connection.target.get_ip_or_hostname(), port)
		target = DCERPCTarget.from_connection_string(
			dcerpc_target_str, 
			proxies=smb_connection.target.proxies, 
			dc_ip = smb_connection.target.dc_ip, 
			domain = smb_connection.target.domain, 
			hostname = smb_connection.target.get_hostname_or_ip()
		)
		auth = DCERPCAuth.from_smb_gssapi(smb_connection.gssapi)
		connection = DCERPC5Connection(auth, target)
		connection.set_auth_type(RPC_C_AUTHN_LEVEL_NONE)
		return EPM(connection, data_representation)

	@staticmethod
	def from_unitarget(target:UniTarget, protocol:str = 'ncacn_ip_tcp', port:int = 135, data_representation = None, credentials = None):
		dcerpc_target_str = r'%s:%s[%s]' % (protocol, target.get_ip_or_hostname(), port)
		target = DCERPCTarget.from_connection_string(
			dcerpc_target_str,
			proxies = target.proxies,
			dc_ip=target.dc_ip,
			domain=target.domain,
			hostname=target.get_hostname_or_ip()
		)
		auth = None
		if credentials is not None:
			auth = DCERPCAuth.from_smb_gssapi(credentials)
		connection = DCERPC5Connection(auth, target)
		if auth is None:
			connection.set_auth_type(RPC_C_AUTHN_LEVEL_NONE)
		return EPM(connection, data_representation)

	@staticmethod
	async def create_connection(target:UniTarget, credential:SPNEGOCredential, remoteIf):
		epm = None
		try:
			epm = EPM.from_unitarget(target)
			_, err = await epm.connect()
			if err is not None:
				raise err

			res, err = await epm.map(remoteIf)
			if err is not None:
				raise err
			
			dcetarget = DCERPCTarget.from_connection_string(res, proxies = target.proxies, dc_ip = target.dc_ip, domain = target.domain)
			dcecred = DCERPCAuth.from_smb_gssapi(credential)
			return DCERPC5Connection(dcecred, dcetarget), None

		except Exception as e:
			return False, e
		finally:
			if epm is not None:
				await epm.disconnect()

	@staticmethod
	async def create_target(ip, remoteIf, proxies:List[UniProxyTarget] = None, dc_ip:str = None, domain:str = None):
		epm = None
		try:
			epm = EPM.from_address(ip, proxies = proxies)
			_, err = await epm.connect()
			if err is not None:
				raise err

			res, err = await epm.map(remoteIf)
			if err is not None:
				raise err
			
			return DCERPCTarget.from_connection_string(res, proxies = proxies, dc_ip = dc_ip, domain = domain), None
		except Exception as e:
			return False, e
		finally:
			if epm is not None:
				await epm.disconnect()

	async def disconnect(self):
		if self.dce is not None:
			await self.dce.disconnect()
		

	async def connect(self, autobind = True):
		try:
			_, err = await self.dce.connect()
			if err is not None:
				raise err
			
			if not autobind:
				return True, None
			return await self.bind()
		except Exception as e:
			return False, e
	
	async def bind(self, uuid = MSRPC_UUID_PORTMAP):
		try:
			_, err = await self.dce.bind(uuid)
			if err is not None:
				raise err
			return True,None
		except Exception as e:
			return False, e

	async def disconnect(self):
		await self.dce.disconnect()
	
	async def request(self, request):
		try:
			return await self.dce.request(request)
		except Exception as e:
			return None, e

	async def map(self, remoteIf):
		try:
			tower = EPMTower()
			interface = EPMRPCInterface()

			interface['InterfaceUUID'] = remoteIf[:16]
			interface['MajorVersion'] = unpack('<H', remoteIf[16:][:2])[0]
			interface['MinorVersion'] = unpack('<H', remoteIf[18:])[0]

			dataRep = EPMRPCDataRepresentation()
			dataRep['DataRepUuid'] = self.data_representation[:16]
			dataRep['MajorVersion'] = unpack('<H', self.data_representation[16:][:2])[0]
			dataRep['MinorVersion'] = unpack('<H', self.data_representation[18:])[0]

			protId = EPMProtocolIdentifier()
			protId['ProtIdentifier'] = FLOOR_RPCV5_IDENTIFIER

			if self.dce.target.rpcprotocol == 'ncacn_np':
				pipeName = EPMPipeName()
				pipeName['PipeName'] = b'\x00'

				hostName = EPMHostName()
				hostName['HostName'] = b('%s\x00' % self.dce.target.ip)
				transportData = pipeName.getData() + hostName.getData()

			elif self.dce.target.rpcprotocol == 'ncacn_ip_tcp':
				portAddr = EPMPortAddr()
				portAddr['IpPort'] = 0

				hostAddr = EPMHostAddr()
				hostAddr['Ip4addr'] = b'\x00\x00\x00\x00' #socket.inet_aton('0.0.0.0')
				transportData = portAddr.getData() + hostAddr.getData()
			elif self.dce.target.rpcprotocol == 'ncacn_http':
				portAddr = EPMPortAddr()
				portAddr['PortIdentifier'] = FLOOR_HTTP_IDENTIFIER
				portAddr['IpPort'] = 0

				hostAddr = EPMHostAddr()
				hostAddr['Ip4addr'] = b'\x00\x00\x00\x00' #socket.inet_aton('0.0.0.0')
				transportData = portAddr.getData() + hostAddr.getData()

			else:
				raise Exception('Unsupported protocol! %s' % self.protocol)

			tower['NumberOfFloors'] = 5
			tower['Floors'] = interface.getData() + dataRep.getData() + protId.getData() + transportData

			request = ept_map()
			request['max_towers'] = 1
			request['map_tower']['tower_length'] = len(tower)
			request['map_tower']['tower_octet_string'] = tower.getData()

			# Under Windows 2003 the Referent IDs cannot be random
			# they must have the following specific values
			# otherwise we get a rpc_x_bad_stub_data exception
			request.fields['obj'].fields['ReferentID'] = 1
			request.fields['map_tower'].fields['ReferentID'] = 2

			resp, err = await self.dce.request(request)
			if err is not None:
				raise err

			tower = EPMTower(b''.join(resp['ITowers'][0]['Data']['tower_octet_string']))
			# Now let's parse the result and return an stringBinding
			result = None
			if self.dce.target.rpcprotocol == 'ncacn_np':
				# Pipe Name should be the 4th floor
				pipeName = EPMPipeName(tower['Floors'][3].getData())
				result = 'ncacn_np:%s[%s]' % (self.dce.target.get_ip_or_hostname(), pipeName['PipeName'].decode('utf-8')[:-1])
			elif self.dce.target.rpcprotocol == 'ncacn_ip_tcp':
				# Port Number should be the 4th floor
				portAddr = EPMPortAddr(tower['Floors'][3].getData())
				result = 'ncacn_ip_tcp:%s[%s]' % (self.dce.target.get_ip_or_hostname(), portAddr['IpPort'])
			elif self.dce.target.rpcprotocol == 'ncacn_http':
				# Port Number should be the 4th floor
				portAddr = EPMPortAddr(tower['Floors'][3].getData())
				result = 'ncacn_http:%s[%s]' % (self.dce.target.get_ip_or_hostname(), portAddr['IpPort'])
			
			return result, None
		except Exception as e:
			return None, e

	
	async def lookup(self, inquiry_type = RPC_C_EP_ALL_ELTS, objectUUID = NULL, ifId = NULL, vers_option = RPC_C_VERS_ALL,  entry_handle = ept_lookup_handle_t(), max_ents = 499):
		try:
			request = ept_lookup()
			request['inquiry_type'] = inquiry_type
			request['object'] = objectUUID
			if ifId != NULL:
				request['Ifid']['Uuid'] = ifId[:16]
				request['Ifid']['VersMajor'] = ifId[16:][:2]
				request['Ifid']['VersMinor'] = ifId[18:]
			else:
				request['Ifid'] = ifId
			request['vers_option'] = vers_option
			request['entry_handle'] = entry_handle
			request['max_ents'] = max_ents
			
			resp, err = await self.dce.request(request)
			if err is not None:
				raise err

			entries = []
			for i in range(resp['num_ents']):
				tmpEntry = {}
				entry = resp['entries'][i]
				tmpEntry['object'] = entry['object'] 
				tmpEntry['annotation'] = b''.join(entry['annotation'])
				tmpEntry['tower'] = EPMTower(b''.join(entry['tower']['tower_octet_string']))
				entries.append(tmpEntry)

			return entries, None
		except Exception as e:
			return None, e

async def amain():
	try:
		from aiosmb.dcerpc.v5 import nrpc
		epm = EPM.from_address('10.10.10.2')
		_, err = await epm.connect()
		if err is not None:
			raise err
		
		res, err = await epm.lookup()
		if err is not None:
			raise err
		print(res)
		print()
		res, err = await epm.map(nrpc.MSRPC_UUID_NRPC)
		if err is not None:
			raise err
		print(res)


	except Exception as e:
		traceback.print_exc()

if __name__ == '__main__':
	import asyncio
	asyncio.run(amain())
	