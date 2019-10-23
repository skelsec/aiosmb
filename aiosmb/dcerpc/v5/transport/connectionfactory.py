from aiosmb.dcerpc.v5.transport.common import DCERPCStringBinding
from aiosmb.dcerpc.v5.transport.tcp import DCERPCTCPTransport
from aiosmb.dcerpc.v5.transport.smb import DCERPCSMBTransport

from aiosmb.dcerpc.v5.connection import DCERPC5Connection

class DCERPCConnectionFactory:
	def __init__(self, original_connection = None):
		self.original_connection = original_connection

	async def get_connection_from_bindstring(self, s):
		string_binding = DCERPCStringBinding(s)
		return await self.get_connection(string_binding)

	async def get_connection(self, sb):
		"""
		Creates a DCERPC5Connection object
		
		"""
		try:
			na = sb.get_network_address()
			ps = sb.get_protocol_sequence()

			if 'ncadg_ip_udp' == ps:
				raise Exception('Not Implemented!')
				
			elif 'ncacn_ip_tcp' == ps:
				port = sb.get_endpoint()
				target = self.original_connection.target.get_copy(ip=na, port = int(port))
				gssapi = self.original_connection.gssapi.get_copy()
				return DCERPC5Connection(gssapi, target), None

			elif 'ncacn_http' == ps:
				raise Exception('Not Implemented!')
				
			elif 'ncacn_np' == ps:
				gssapi = self.original_connection.gssapi.get_copy()
				
				named_pipe = sb.get_endpoint()
				print(named_pipe)
				print(sb)
				if named_pipe:
					named_pipe = named_pipe[len(r'\pipe'):]
					return DCERPCSMBTransport(self.original_connection, na, filename = named_pipe)
				else:
					return DCERPCSMBTransport(self.original_connection, na)

				target = self.original_connection.target.get_copy(ip=na, port = int(port))
				
				return DCERPC5Connection(gssapi, target), None

			elif 'ncalocal' == ps:
				raise Exception('Not Implemented!')
				#named_pipe = sb.get_endpoint()
				#return LOCALTransport(filename = named_pipe)
			else:
				raise DCERPCException("Unknown protocol sequence.")
		except Exception as e:
			return None, e