import ipaddress
import enum


class SMBTargetProxySecretType(enum.Enum):
	NONE = 'NONE'

class SMBTargetProxyServerType(enum.Enum):
	SOCKS5 = 'SOCKS5'

class SMBTargetProxy:
	def __init__(self):
		self.ip = None
		self.port = 1080
		self.timeout = 5
		self.proxy_type = None
		self.username = None
		self.domain = None
		self.secret = None
		self.secret_type = None #SMBCredentialsSecretType
		
	def to_target_string(self):
		pass
	
	@staticmethod
	def from_connection_string(s):
		"""
		protocol/domain/user/secret-type:secret@proxy_server:port
		"""
		port = 1080
		t, target = s.rsplit('@', 1)
		ip = target
		if target.find(':') != -1:
			ip, port = target.split(':')
			
		st = SMBTargetProxy()
		st.port = int(port)
		st.ip = ip

		t, secret = t.split(':', 1)
		elems = t.split('/')
		st.proxy_type = SMBTargetProxyServerType(elems[0].upper())
		st.domain = elems[1]
		st.user = elems[2]
		st.secret_type = SMBTargetProxySecretType(elems[3].upper())
		st.secret = secret
	
		return st
		
	def __str__(self):
		t = '==== SMBTargetProxy ====\r\n'
		for k in self.__dict__:
			print(k)
			t += '%s: %s\r\n' % (k, self.__dict__[k])
			
		return t
		
		
def test():
	t1 = 'SOCKS5///NONE:@10.1.1.1:22'
	t2 = 'SOCKS5/alma/korte/none:asdfasdfadsf@10.33.11.22:4444'
	s = SMBTargetProxy.from_connection_string(t1)
	print(str(s))
	s = SMBTargetProxy.from_connection_string(t2)
	print(str(s))

	
if __name__ == '__main__':
	test()