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
from urllib.parse import urlparse, parse_qs
from typing import List
from asysocks.unicomm.utils.paramprocessor import str_one, int_one, bool_one

from asysocks.unicomm.common.target import UniTarget, UniProto
from asysocks.unicomm.common.proxy import UniProxyProto, UniProxyTarget

from aiosmb.protocol.common import NegotiateDialects, SMB2_NEGOTIATE_DIALTECTS_2, SMB2_NEGOTIATE_DIALTECTS_3, SMB2_NEGOTIATE_DIALTECTS
from aiosmb.protocol.smb2.commands.negotiate import SMB2CompressionType

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

smburlconnection_param2var = {
	'TCP' : UniProto.CLIENT_TCP,
	'UDP' : UniProto.CLIENT_UDP,
	'QUIC' : UniProto.CLIENT_QUIC,
}

smbtarget_url_params = {
	'fragment' : int_one,
	'compress' : int_one,
	'compress_min' : int_one,
	'compress_algorithms' : str_one,
}

_compression_algorithm_names = {
	'lznt1': SMB2CompressionType.LZNT1,
	'lz77': SMB2CompressionType.LZ77,
	'lz77_huffman': SMB2CompressionType.LZ77_Huffman,
	'lz4': SMB2CompressionType.LZ4,
}


def _parse_compression_algorithms(value):
	if value in (None, ''):
		return None
	algorithms = []
	for name in value.split(','):
		key = name.strip().lower().replace('-', '_')
		try:
			algorithm = _compression_algorithm_names[key]
		except KeyError:
			raise ValueError('Unsupported unchained SMB compression algorithm: %s' % name)
		if algorithm in algorithms:
			raise ValueError('SMB compression algorithms must be unique')
		algorithms.append(algorithm)
	if not algorithms:
		raise ValueError('At least one SMB compression algorithm must be selected')
	return tuple(algorithms)


class SMBTarget(UniTarget):
	"""
	"""
	def __init__(self, ip:str = None, 
						port:int = 445, 
						hostname:str = None, 
						timeout:int = 5, 
						dc_ip:str =None, 
						domain:str = None, 
						proxies:List[UniProxyTarget] = None,
						protocol:UniProto = UniProto.CLIENT_TCP,
						dns:str = None,
						path:str = None,
						compression:bool = False,
						fragment:int = None,
						compression_min_size:int = 4096,
						compression_algorithms = None):
		UniTarget.__init__(self, ip, port, protocol, timeout, hostname = hostname, proxies = proxies, domain = domain, dc_ip = dc_ip, dns=dns)
		
		self.path:str = path #for holding remote file path
		self.preferred_dialects:SMBConnectionDialect = SMB2_NEGOTIATE_DIALTECTS_2
		self.fragment = fragment
		if compression_algorithms is not None:
			compression_algorithms = tuple(compression_algorithms)
			if not compression_algorithms:
				raise ValueError('At least one SMB compression algorithm must be selected')
			if any(
				not isinstance(algorithm, SMB2CompressionType) or
				algorithm in (SMB2CompressionType.NONE, SMB2CompressionType.Pattern_V1)
				for algorithm in compression_algorithms
			):
				raise ValueError('Only unchained SMB compression algorithms may be selected')
			if len(set(compression_algorithms)) != len(compression_algorithms):
				raise ValueError('SMB compression algorithms must be unique')
		self.compression:bool = compression
		self.compression_min_size:int = compression_min_size
		self.compression_algorithms = compression_algorithms
		if self.compression_min_size < 1:
			raise ValueError('compression_min_size must be positive')
		
		#this is mostly for advanced users
		self.MaxTransactSize:int = 0x100000
		self.MaxReadSize:int = 0x100000
		self.MaxWriteSize:int = 0x100000
		self.PendingTimeout:int = 5
		self.PendingMaxRenewal:int = None

		self.calc_fragment()
		
	def calc_fragment(self):
		if self.fragment is not None:
			fs = 0x100000
			if self.fragment == 5:
				fs = 5*1024
			elif self.fragment == 4:
				fs = 7*1024
			elif self.fragment == 3:
				fs = 10*1024
			elif self.fragment == 2:
				fs = 500*1024
			elif self.fragment == 1:
				fs = 5000*1024
			
			self.MaxTransactSize = fs
			self.MaxReadSize = fs
			self.MaxWriteSize = fs


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
			protocol = self.protocol,
			compression = self.compression,
			fragment = self.fragment,
			compression_min_size = self.compression_min_size,
			compression_algorithms = self.compression_algorithms,
		)

		t.MaxTransactSize = self.MaxTransactSize
		t.MaxReadSize = self.MaxReadSize
		t.MaxWriteSize = self.MaxWriteSize
		t.PendingTimeout = self.PendingTimeout
		t.PendingMaxRenewal = self.PendingMaxRenewal

		return t
	
	@staticmethod
	def create_dummy(proxies = None):
		return SMBTarget(
			ip = '999.999.999.999',
			port = 445,
			hostname = 'dummy',
			timeout = 5,
			proxies = proxies
		)
	
	@staticmethod
	def from_url(connection_url):
		url_e = urlparse(connection_url)
		schemes = url_e.scheme.upper().split('+')
		connection_tags = schemes[0].split('-')
		if len(connection_tags) > 1:
			dialect = SMBConnectionDialect(connection_tags[0])
			protocol = smburlconnection_param2var[connection_tags[1]]
		else:
			dialect = SMBConnectionDialect(connection_tags[0])
			protocol = UniProto.CLIENT_TCP
		
		if url_e.port:
			port = url_e.port
		elif protocol == UniProto.CLIENT_TCP:
			port = 445
		elif protocol == UniProto.CLIENT_QUIC:
			port = 443
		else:
			raise Exception('Port must be provided!')
		
		path = None
		if url_e.path not in ['/', '', None]:
			path = url_e.path
		
		unitarget, extraparams = UniTarget.from_url(connection_url, protocol, port, smbtarget_url_params)
		compression = extraparams.get('compress', False)
		compression_min_size = extraparams.get('compress_min')
		if compression_min_size is None:
			compression_min_size = 4096
		compression_algorithms = _parse_compression_algorithms(
			extraparams.get('compress_algorithms')
		)
		fragment = extraparams.get('fragment')

		target = SMBTarget(
			ip = unitarget.ip,
			port = unitarget.port,
			hostname = unitarget.hostname,
			timeout = unitarget.timeout,
			dc_ip = unitarget.dc_ip,
			domain = unitarget.domain,
			proxies = unitarget.proxies,
			protocol = unitarget.protocol,
			dns = unitarget.dns,
			path = path,
			compression=compression,
			fragment = fragment,
			compression_min_size = compression_min_size,
			compression_algorithms = compression_algorithms,
		)
		target.update_dialect(dialect)
		return target



	
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