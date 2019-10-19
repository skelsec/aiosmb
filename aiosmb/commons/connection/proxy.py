import ipaddress
import enum
from urllib.parse import urlparse, parse_qs


class SMBProxySecretType(enum.Enum):
	NONE = 'NONE'
	PLAIN = 'PLAIN'

class SMBProxyType(enum.Enum):
	SOCKS5 = 'SOCKS5'
	SOCKS5_SSL = 'SOCKS5_SSL'
	MULTIPLEXOR = 'MULTIPLEXOR'
	MULTIPLEXOR_SSL = 'MULTIPLEXOR_SSL'

class SMBProxy:
	def __init__(self, 
				ip = None,
				port = None,
				timeout = 5,
				proxy_type = None,
				username = None,
				domain = None,
				secret = None,
				secret_type = SMBProxySecretType.NONE,
				agent_id = None):
		self.ip = ip
		self.port = port
		self.timeout = timeout
		self.type = proxy_type
		self.username = username
		self.domain = domain
		self.secret = secret
		self.secret_type = secret_type
		self.agent_id = agent_id #used by multiplexor only
		self.settings = {}
	
	@staticmethod
	def from_url(url_str):
		proxy = SMBProxy()
		url_e = urlparse(url_str)
		if url_e.query is None:
			return None
		
		query = parse_qs(url_e.query)
		if 'proxytype' not in query and 'sametype' not in query:
			return None

		for k in query:
			if k.startswith('proxy') or k.startswith('same'):
				key = 'same'
				if k.startswith('proxy'):
					key = 'proxy'
				
				if k == key+'type':
					proxy.type = SMBProxyType(query[k][0].replace('-','_').upper())
				elif k == key+'user':
					proxy.username = query[k][0]
				elif k == key+'domain':
					proxy.domain = query[k][0]
				elif k == key+'pass':
					proxy.secret = query[k][0]
				elif k == key+'host':
					proxy.ip = query[k][0]
				elif k == key+'port':
					proxy.port = int(query[k][0])
				elif k == key+'timeout':
					proxy.timeout = int(query[k][0])
				elif k == key+'agentid':
					proxy.agent_id = query[k][0]
				else:
					proxy.settings[k[len(key):]] = query[k] #the result is a list for each entry because this preprocessor is not aware which elements should be lists!
		
		if proxy.secret is not None:
			proxy.secret_type = SMBProxySecretType.PLAIN
		else:
			proxy.secret_type = SMBProxySecretType.NONE

		if proxy.ip is None:
			raise Exception('Proxy server specified with missing servber address! (add proxyhost to params)')
		
		if proxy.type in [SMBProxyType.MULTIPLEXOR_SSL, SMBProxyType.MULTIPLEXOR]:
			if proxy.agent_id is None:
				raise Exception('MULTIPLEXOR proxy requires agentid to be set!')

		return proxy

	
	@staticmethod
	def from_connection_string(s):
		"""
		URL format required
		socks5://user:password@ipaddress:port
		socks5+ssl://user:password@ipaddress:port
		multiplexor://user:password@ipaddress:port/agentid
		"""
		st = SMBProxy()
		o = urlparse(s)

		st.type = SMBProxyType(o.scheme.upper().replace('+','_'))
		st.ip = o.hostname
		st.username = o.username
		st.secret = o.password
		st.port = int(o.port)
		if st.secret is not None:
			st.secret_type = SMBProxySecretType.PLAIN
		
		if st.type in [SMBProxyType.MULTIPLEXOR, SMBProxyType.MULTIPLEXOR_SSL]:
			st.agent_id = o.path.replace('/','')
		
		return st
		
	def __str__(self):
		t = '==== SMBProxy ====\r\n'
		for k in self.__dict__:
			t += '%s: %s\r\n' % (k, self.__dict__[k])
			
		return t
		
		
def test():
	t = ['socks5://10.10.10.1',
			'socks5+ssl://10.10.10.1',
			'socks5+ssl://admin:password@10.10.10.1',
			'multiplexor+ssl://admin:password@10.10.10.1/alma',
	]
	for x in t:
		s = SMBProxy.from_connection_string(x)
		print(str(s))

	
if __name__ == '__main__':
	test()