#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
# Comments:
#


import ipaddress
import enum
import copy

from aiosmb.protocol.common import NegotiateDialects, SMB2_NEGOTIATE_DIALTECTS_2, SMB2_NEGOTIATE_DIALTECTS_3, SMB2_NEGOTIATE_DIALTECTS

class SMBConnectionDialect(enum.Enum):
	SMB = 'SMB' #any, will us a wildcard because SMB1 is not implremented
	SMB2 = 'SMB2' #will offer all v2 versions
	SMB3 = 'SMB3' #will offer all v3 versions
	SMB202 = 'SMB202'
	SMB210 = 'SMB210'
	#SMB222 = 'SMB222'
	#SMB224 = 'SMB224'
	SMB300 = 'SMB300'
	SMB302 = 'SMB302'
	#SMB310 = 'SMB310'
	SMB311 = 'SMB311'

smb_negotiate_dialect_lookup = {
	SMBConnectionDialect.SMB202 : NegotiateDialects.SMB202,
	SMBConnectionDialect.SMB210 : NegotiateDialects.SMB210,
	#SMBConnectionDialect.SMB222 : NegotiateDialects.SMB222,
	#SMBConnectionDialect.SMB224 : NegotiateDialects.SMB224,
	SMBConnectionDialect.SMB300 : NegotiateDialects.SMB300,
	SMBConnectionDialect.SMB302 : NegotiateDialects.SMB302,
	#SMBConnectionDialect.SMB310 : NegotiateDialects.SMB310,
	SMBConnectionDialect.SMB311 : NegotiateDialects.SMB311,
}

class SMBConnectionProtocol(enum.Enum):
	TCP = 'TCP'
	UDP = 'UDP'

class SMBTarget:
	"""
	"""
	def __init__(self, ip = None, 
						port = 445, 
						hostname = None, 
						timeout = 1, 
						dc_ip=None, 
						domain = None, 
						proxy = None,
						protocol = SMBConnectionProtocol.TCP):
		self.ip = ip
		self.port = port
		self.hostname = hostname
		self.timeout = timeout
		self.dc_ip = dc_ip
		self.domain = domain
		self.proxy = proxy
		self.protocol = protocol
		self.preferred_dialects = SMB2_NEGOTIATE_DIALTECTS_2


	def update_dialect(self, dialect):
		if isinstance(dialect, SMBConnectionDialect) is False:
			raise Exception('dialect must be a type of SMBConnectionDialect')
		if dialect == SMBConnectionDialect.SMB:
			self.preferred_dialects = SMB2_NEGOTIATE_DIALTECTS
			self.preferred_dialects[NegotiateDialects.WILDCARD] = 1
		elif dialect == SMBConnectionDialect.SMB2:
			self.preferred_dialects = SMB2_NEGOTIATE_DIALTECTS_2
		elif dialect == SMBConnectionDialect.SMB3:
			self.preferred_dialects = SMB2_NEGOTIATE_DIALTECTS_3
			
		else:
			self.preferred_dialects = {
				smb_negotiate_dialect_lookup[dialect] : 1,
				NegotiateDialects.WILDCARD : 1,
			}
		return

	def to_target_string(self):
		return 'cifs/%s@%s' % (self.hostname, self.domain)

	def get_copy(self, ip, port, hostname = None):
		t = SMBTarget(
			ip = ip, 
			port = port, 
			hostname = hostname, 
			timeout = self.timeout, 
			dc_ip= self.dc_ip, 
			domain = self.domain, 
			proxy = copy.deepcopy(self.proxy),
			protocol = self.protocol
		)

		self.preferred_dialects
		return t
	
	@staticmethod
	def from_connection_string(s):
		port = 445
		dc = None
		
		_, target = s.rsplit('@', 1)
		if target.find('/') != -1:
			target, dc = target.split('/')
			
		if target.find(':') != -1:
			target, port = target.split(':')
			
		st = SMBTarget()
		st.port = port
		st.dc_ip = dc
		st.domain, _ = s.split('/', 1)
		
		try:
			st.ip = str(ipaddress.ip_address(target))
		except:
			st.hostname = target
	
		return st
		
	def get_ip(self):
		if not self.ip and not self.hostname:
			raise Exception('SMBTarget must have ip or hostname defined!')
		return self.ip if self.ip is not None else self.hostname
		
	def get_hostname(self):
		return self.hostname
	
	def get_hostname_or_ip(self):
		if self.hostname:
			return self.hostname
		return self.ip
	
	def get_port(self):
		return self.port
		
	def __str__(self):
		t = '==== SMBTarget ====\r\n'
		for k in self.__dict__:
			t += '%s: %s\r\n' % (k, self.__dict__[k])
			
		return t
		
		
def test():
	s = 'TEST/victim/ntlm/nt:AAAAAAAA@10.10.10.2:445'
	creds = SMBTarget.from_connection_string(s)
	print(str(creds))
	
	s = 'TEST/victim/sspi@10.10.10.2:445/aaaa'
	creds = SMBTarget.from_connection_string(s)
	
	print(str(creds))
	
if __name__ == '__main__':
	test()