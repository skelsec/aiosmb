import ipaddress
import copy

from aiosmb.commons.connection.proxy import SMBProxy
from aiosmb.dcerpc.v5.common.connection.connectionstring import DCERPCStringBinding


# TODO: this is disgusting, need to clean it up :()

class DCERPCTargetType:
	UDP = 'UDP'
	TCP = 'TCP'
	SMB = 'SMB'
	HTTP = 'HTTP'
	LOCAL = 'LOCAL'


class DCERPCTarget:
	def __init__(self, connection_string:str, ttype, proxy = None, timeout = 1):
		self.ip = None
		self.hostname = None
		self.dc_ip = None
		self.domain = None
		self.smb_connection = None #not all types have this
		self.connection_string = connection_string
		self.type = ttype
		self.timeout = timeout
		self.proxy = None
		self.protocol = None #eg. ncap_np

	def get_hostname_or_ip(self):
		if self.smb_connection is not None:
			return self.smb_connection.target.get_hostname_or_ip()
		if self.hostname is None:
			return self.ip
		return self.hostname

	def set_hostname_or_ip(self, ip):
		try:
			self.ip = str(ipaddress.ip_address(ip))
		except:
			self.hostname = ip
			self.ip = ip
	
	def to_target_string(self) -> str:
		if self.hostname is None:
			raise Exception('Hostname is None!')
		if self.domain is None:
			raise Exception('Domain is None!')
		return 'cifs/%s@%s' % (self.hostname, self.domain)

	@staticmethod
	def from_smbconnection(smb_connection, pipe = None):
		if pipe is None:
			target = DCERPCSMBTarget(None, smb_connection.target.get_hostname_or_ip(), smb_connection=smb_connection, timeout = smb_connection.target.timeout)
		else:
			target = DCERPCSMBTarget(None, smb_connection.target.get_hostname_or_ip(), pipe, smb_connection=smb_connection, timeout = smb_connection.target.timeout)
		return target

	@staticmethod
	def from_connection_string(s, smb_connection = None, timeout = 1, proxy:SMBProxy = None, dc_ip:str = None, domain:str = None):
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
			target = DCERPCTCPTarget(connection_string, na, port, timeout = timeout, dc_ip=dc_ip, domain = domain)
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

		if proxy is not None:
			tp = copy.deepcopy(proxy)
			if isinstance(tp.target, list):
				tp.target[-1].endpoint_ip = target.ip
				tp.target[-1].endpoint_port = target.port
				tp.target[-1].timeout = target.timeout
			else:
				tp.target.endpoint_ip = target.ip
				tp.target.endpoint_port = target.port
				tp.target.timeout = target.timeout
			
			target.proxy = tp


		if smb_connection is not None:
			if smb_connection.target.proxy is not None:
				target.proxy = copy.deepcopy(smb_connection.target.proxy)
			
		return target

	def __str__(self):
		t = '==== DCERPCTarget ====\r\n'
		for k in self.__dict__:
			t += '%s: %s\r\n' % (k, self.__dict__[k])
			
		return t


class DCERPCTCPTarget(DCERPCTarget):
	def __init__(self, connection_string, ip, port, timeout = 1, proxy = None, dc_ip:str = None, domain:str = None):
		DCERPCTarget.__init__(self, connection_string, DCERPCTargetType.TCP, timeout = timeout, proxy=proxy)
		self.set_hostname_or_ip(ip)
		self.port = int(port)
		self.protocol = 'ncacn_ip_tcp'
		self.dc_ip = dc_ip
		self.domain = domain

class DCERPCUDPTarget(DCERPCTarget):
	def __init__(self, connection_string, ip, port, timeout = 1):
		DCERPCTarget.__init__(self, connection_string, DCERPCTargetType.UDP, timeout = timeout)
		self.set_hostname_or_ip(ip)
		self.port = int(port)
		self.protocol = 'ncadg_ip_udp'

class DCERPCSMBTarget(DCERPCTarget):
	def __init__(self, connection_string, ip, pipe = None, smb_connection = None, timeout = 1):
		DCERPCTarget.__init__(self, connection_string, DCERPCTargetType.SMB, timeout = timeout)
		self.set_hostname_or_ip(ip)
		self.pipe = pipe
		self.smb_connection = smb_connection #storing the smb connection if already exists...
		self.dc_ip = self.smb_connection.target.dc_ip
		self.protocol = 'ncacn_np'

class DCERPCHTTPTarget(DCERPCTarget):
	def __init__(self, connection_string, ip, port, timeout = 1):
		DCERPCTarget.__init__(self, connection_string, DCERPCTargetType.HTTP, timeout = timeout)
		self.set_hostname_or_ip(ip)
		self.port = int(port)
		self.protocol = 'ncacn_http'

class DCERPCLocalTarget(DCERPCTarget):
	def __init__(self, connection_string, ip, port, timeout = 1):
		DCERPCTarget.__init__(self, connection_string, DCERPCTargetType.LOCAL, timeout = timeout)
		self.set_hostname_or_ip(ip)
		self.port = int(port)
		self.protocol = 'ncalocal'



if __name__ == '__main__':
	s = ''
	target = DCERPCTarget.from_connection_string(s)
	


