from aiosmb.dcerpc.v5.epm import *
from aiosmb.dcerpc.v5.common.connection.connectionstring import DCERPCStringBinding
from aiosmb.dcerpc.v5.connection import DCERPC5Connection
from aiosmb.dcerpc.v5.common.connection.target import DCERPCTarget
from aiosmb.dcerpc.v5.common.connection.authentication import DCERPCAuth

from aiosmb.commons.utils.decorators import red, rr

"""
EPM is a bit special interface, as it seems it doesn't require authentication?
So it should have been easy to just create a static method to resolv endpoints.
However there is a bit of a problem whan you want to use it with proxyies,
hence an interface needed to be created that takes the proxy settings into account
"""
class EPM:
	def __init__(self, smb_connection, protocol = 'ncacn_np', data_representation = None, port = 135):
		self.smb_connection = smb_connection
		self.protocol = protocol
		self.port = port
		self.data_representation = data_representation
		if data_representation is None:
			self.data_representation = uuidtup_to_bin(('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0'))

		self.dce = None

	def get_connection_from_stringbinding(self, s):
		target = DCERPCTarget.from_connection_string(s, smb_connection = self.smb_connection)
		#target.proxy = self.smb_connection.target.proxy
		auth = DCERPCAuth.from_smb_gssapi(self.smb_connection.gssapi)
		return DCERPC5Connection(auth, target)

	async def disconnect(self):
		await self.dce.disconnect()

	async def connect(self):
		try:
			dcerpc_target_str = r'%s:%s[%s]' % (self.protocol, self.smb_connection.target.ip, self.port)
			self.dce = self.get_connection_from_stringbinding(dcerpc_target_str)

			await rr(self.dce.connect())
			await rr(self.dce.bind(MSRPC_UUID_PORTMAP))

			return True,None
		except Exception as e:
			return False, e

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

			if self.protocol == 'ncacn_np':
				pipeName = EPMPipeName()
				pipeName['PipeName'] = b'\x00'

				hostName = EPMHostName()
				#hostName['HostName'] = b('%s\x00' % self.smb_connection.target.get_hostname_or_ip())
				hostName['HostName'] = b('%s\x00' % self.smb_connection.target.ip)
				transportData = pipeName.getData() + hostName.getData()

			elif self.protocol == 'ncacn_ip_tcp':
				portAddr = EPMPortAddr()
				portAddr['IpPort'] = 0

				hostAddr = EPMHostAddr()
				import socket
				hostAddr['Ip4addr'] = socket.inet_aton('0.0.0.0')
				transportData = portAddr.getData() + hostAddr.getData()
			elif self.protocol == 'ncacn_http':
				portAddr = EPMPortAddr()
				portAddr['PortIdentifier'] = FLOOR_HTTP_IDENTIFIER
				portAddr['IpPort'] = 0

				hostAddr = EPMHostAddr()
				import socket
				hostAddr['Ip4addr'] = socket.inet_aton('0.0.0.0')
				transportData = portAddr.getData() + hostAddr.getData()

			else:
				return None, Exception('Unsupported protocol! %s' % self.protocol)

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
			if self.protocol == 'ncacn_np':
				# Pipe Name should be the 4th floor
				pipeName = EPMPipeName(tower['Floors'][3].getData())
				result = 'ncacn_np:%s[%s]' % (self.smb_connection.target.ip, pipeName['PipeName'].decode('utf-8')[:-1])
			elif self.protocol == 'ncacn_ip_tcp':
				# Port Number should be the 4th floor
				portAddr = EPMPortAddr(tower['Floors'][3].getData())
				result = 'ncacn_ip_tcp:%s[%s]' % (self.smb_connection.target.ip, portAddr['IpPort'])
			elif self.protocol == 'ncacn_http':
				# Port Number should be the 4th floor
				portAddr = EPMPortAddr(tower['Floors'][3].getData())
				result = 'ncacn_http:%s[%s]' % (self.smb_connection.target.ip, portAddr['IpPort'])
			
			return result, None
		except Exception as e:
			return None, e

	@red
	async def lookup(self, inquiry_type = RPC_C_EP_ALL_ELTS, objectUUID = NULL, ifId = NULL, vers_option = RPC_C_VERS_ALL,  entry_handle = ept_lookup_handle_t(), max_ents = 499):
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
		
		resp, _ = await rr(self.dce.request(request))

		entries = []
		for i in range(resp['num_ents']):
			tmpEntry = {}
			entry = resp['entries'][i]
			tmpEntry['object'] = entry['object'] 
			tmpEntry['annotation'] = b''.join(entry['annotation'])
			tmpEntry['tower'] = EPMTower(b''.join(entry['tower']['tower_octet_string']))
			entries.append(tmpEntry)

		return entries, None
	