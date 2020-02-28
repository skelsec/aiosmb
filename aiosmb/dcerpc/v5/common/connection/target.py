import enum
import copy

from aiosmb.dcerpc.v5.common.connection.connectionstring import DCERPCStringBinding


class DCERPCTargetType:
	UDP = 'UDP'
	TCP = 'TCP'
	SMB = 'SMB'
	HTTP = 'HTTP'
	LOCAL = 'LOCAL'


class DCERPCTarget:
	def __init__(self, connection_string, ttype, proxy = None, timeout = 1):
		self.ip = None
		self.connection_string = connection_string
		self.type = ttype
		self.timeout = timeout
		self.proxy = None

	def get_hostname_or_ip(self):
		return self.ip

	@staticmethod
	def from_connection_string(s, smb_connection = None, timeout = 1):
		if isinstance(s, str):
			connection_string = DCERPCStringBinding(s)
		elif isinstance(s, DCERPCStringBinding):
			connection_string = s
		else:
			raise Exception('Unknown string binding type %s' % type(s))
			
		na = connection_string.get_network_address()
		ps = connection_string.get_protocol_sequence()
		if ps == 'ncadg_ip_udp':
			raise Exception('DCERPC UDP not implemented')
			port = connection_string.get_endpoint()
			target = DCERPCUDPTarget(connection_string, na, int(port), timeout = timeout)
		elif ps == 'ncacn_ip_tcp':
			port = connection_string.get_endpoint()
			target = DCERPCTCPTarget(connection_string, na, port, timeout = timeout)
		elif ps == 'ncacn_http':
			raise Exception('DCERPC HTTP not implemented')
			target = DCERPCHTTPTarget(connection_string, na, int(port), timeout = timeout)
		elif ps == 'ncacn_np':
			named_pipe = connection_string.get_endpoint()
			if named_pipe:
				named_pipe = named_pipe[len(r'\pipe'):]
				target = DCERPCSMBTarget(connection_string, na, named_pipe, smb_connection=smb_connection, timeout = timeout)
			else:
				 target = DCERPCSMBTarget(connection_string, na, smb_connection=smb_connection, timeout = timeout)
		elif ps == 'ncalocal':
			raise Exception('DCERPC LOCAL not implemented')
			target = DCERPCLocalTarget(connection_string, na, int(port), timeout = timeout)
		
		else:
			raise Exception('Unknown DCERPC protocol %s' % ps)

		if smb_connection.target.proxy is not None:
			target.proxy = copy.deepcopy(smb_connection.target.proxy)
			
		return target

	def __str__(self):
		t = '==== DCERPCTarget ====\r\n'
		for k in self.__dict__:
			t += '%s: %s\r\n' % (k, self.__dict__[k])
			
		return t


class DCERPCTCPTarget(DCERPCTarget):
	def __init__(self, connection_string, ip, port, timeout = 1):
		DCERPCTarget.__init__(self, connection_string, DCERPCTargetType.TCP, timeout = timeout)
		self.ip = ip
		self.port = int(port)

class DCERPCUDPTarget(DCERPCTarget):
	def __init__(self, connection_string, ip, port, timeout = 1):
		DCERPCTarget.__init__(self, connection_string, DCERPCTargetType.UDP, timeout = timeout)
		self.ip = ip
		self.port = int(port)

class DCERPCSMBTarget(DCERPCTarget):
	def __init__(self, connection_string, ip, pipe = None, smb_connection = None, timeout = 1):
		DCERPCTarget.__init__(self, connection_string, DCERPCTargetType.SMB, timeout = timeout)
		self.ip = ip
		self.pipe = pipe
		self.smb_connection = smb_connection #storing the smb connection is already exists...

class DCERPCHTTPTarget(DCERPCTarget):
	def __init__(self, connection_string, ip, port, timeout = 1):
		DCERPCTarget.__init__(self, connection_string, DCERPCTargetType.HTTP, timeout = timeout)
		self.ip = ip
		self.port = int(port)

class DCERPCLocalTarget(DCERPCTarget):
	def __init__(self, connection_string, ip, port, timeout = 1):
		DCERPCTarget.__init__(self, connection_string, DCERPCTargetType.LOCAL, timeout = timeout)
		self.ip = ip
		self.port = int(port)


if __name__ == '__main__':
	s = ''
	target = DCERPCTarget.from_connection_string(s)
	


