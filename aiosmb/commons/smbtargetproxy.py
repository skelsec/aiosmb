import ipaddress
import enum
from urllib.parse import urlparse


class SMBTargetProxySecretType(enum.Enum):
	NONE = 'NONE'
	PLAIN = 'PLAIN'

class SMBTargetProxyServerType(enum.Enum):
	SOCKS5 = 'SOCKS5'
	SOCKS5_SSL = 'SOCKS5_SSL'
	MULTIPLEXOR = 'MULTIPLEXOR'
	MULTIPLEXOR_SSL = 'MULTIPLEXOR_SSL'



class SMBTargetProxy:
	def __init__(self, ip = None,
				port = None,
				timeout = 5,
				proxy_type = None,
				username = None,
				domain = None,
				secret = None,
				secret_type = SMBTargetProxySecretType.NONE,
				agent_id = None):
		self.ip = ip
		self.port = port
		self.timeout = timeout
		self.proxy_type = proxy_type
		self.username = username
		self.domain = domain
		self.secret = secret
		self.secret_type = secret_type
		self.agent_id = agent_id #used by multiplexor only
		
	def to_target_string(self):
		pass
	
	@staticmethod
	def from_connection_string(s):
		"""
		URL format required
		socks5://user:password@ipaddress:port
		socks5+ssl://user:password@ipaddress:port
		multiplexor://user:password@ipaddress:port/agentid
		"""
		st = SMBTargetProxy()
		o = urlparse(s)

		st.proxy_type = SMBTargetProxyServerType(o.scheme.upper().replace('+','_'))
		st.ip = o.hostname
		st.username = o.username
		st.secret = o.password
		st.port = int(o.port)
		if st.secret is not None:
			st.secret_type = SMBTargetProxySecretType.PLAIN
		
		if st.proxy_type in [SMBTargetProxyServerType.MULTIPLEXOR, SMBTargetProxyServerType.MULTIPLEXOR_SSL]:
			st.agent_id = o.path.replace('/','')
		
		return st
		
	def __str__(self):
		t = '==== SMBTargetProxy ====\r\n'
		for k in self.__dict__:
			print(k)
			t += '%s: %s\r\n' % (k, self.__dict__[k])
			
		return t
		
		
def test():
	t = ['socks5://10.10.10.1',
			'socks5+ssl://10.10.10.1',
			'socks5+ssl://admin:password@10.10.10.1',
			'multiplexor+ssl://admin:password@10.10.10.1/alma',
	]
	for x in t:
		s = SMBTargetProxy.from_connection_string(x)
		print(str(s))

	
if __name__ == '__main__':
	test()