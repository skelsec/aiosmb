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
from typing import List

from asysocks.unicomm.common.target import UniTarget, UniProto
from asysocks.unicomm.common.proxy import UniProxyProto, UniProxyTarget

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

class SMBTarget(UniTarget):
	"""
	"""
	def __init__(self, ip:str = None, 
						port:int = 445, 
						hostname:str = None, 
						timeout:int = 1, 
						dc_ip:str =None, 
						domain:str = None, 
						proxies:List[UniProxyTarget] = None,
						protocol:UniProto = UniProto.CLIENT_TCP,
						path:str = None):
		UniTarget.__init__(self, ip, port, protocol, timeout, hostname = hostname, proxies = proxies, domain = domain, dc_ip = dc_ip)
		
		self.path:str = path #for holding remote file path
		self.preferred_dialects:SMBConnectionDialect = SMB2_NEGOTIATE_DIALTECTS_2
		
		#this is mostly for advanced users
		self.MaxTransactSize:int = 0x100000
		self.MaxReadSize:int = 0x100000
		self.MaxWriteSize:int = 0x100000
		self.PendingTimeout:int = 5
		self.PendingMaxRenewal:int = None
		self.compression:bool = False


	def update_dialect(self, dialect:SMBConnectionDialect) -> None: 
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

	def to_target_string(self) -> str:
		return 'cifs/%s@%s' % (self.hostname, self.domain)

	def get_copy(self, ip, port, hostname = None):
		t = SMBTarget(
			ip = ip, 
			port = port, 
			hostname = hostname, 
			timeout = self.timeout, 
			dc_ip= self.dc_ip, 
			domain = self.domain, 
			proxies = copy.deepcopy(self.proxies),
			protocol = self.protocol
		)

		t.MaxTransactSize = self.MaxTransactSize
		t.MaxReadSize = self.MaxReadSize
		t.MaxWriteSize = self.MaxWriteSize
		t.PendingTimeout = self.PendingTimeout
		t.PendingMaxRenewal = self.PendingMaxRenewal

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
		
	def __str__(self):
		t = '==== SMBTarget ====\r\n'
		for k in self.__dict__:
			if isinstance(self.__dict__[k], list):
				for x in self.__dict__[k]:
					t += '    %s: %s\r\n' % (k, x)
			else:
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