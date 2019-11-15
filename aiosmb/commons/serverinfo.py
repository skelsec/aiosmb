
from aiosmb.authentication.ntlm.structures.avpair import AVPAIRType
from aiosmb.wintypes.dtyp.structures.filetime import FILETIME
import datetime

class NTLMServerInfo:
	def __init__(self):
		self.domainname = None
		self.computername = None
		self.dnscomputername = None
		self.dnsdomainname = None
		self.local_time = None
		self.dnsforestname = None
		self.os_major_version = None
		self.os_minor_version = None
		self.os_build = None
		self.os_guess = None
	
	@staticmethod
	def from_challenge(challenge):
		si = NTLMServerInfo()
		ti = challenge.TargetInfo
		for k in ti:
			if k == AVPAIRType.MsvAvNbDomainName:
				si.domainname = ti[k]
			elif k == AVPAIRType.MsvAvNbComputerName:
				si.computername = ti[k]
			elif k == AVPAIRType.MsvAvDnsDomainName:
				si.dnsdomainname = ti[k]
			elif k == AVPAIRType.MsvAvDnsComputerName:
				si.dnscomputername = ti[k]
			elif k == AVPAIRType.MsvAvDnsTreeName:
				si.dnsforestname = ti[k]
			elif k == AVPAIRType.MsvAvTimestamp:
				if isinstance(ti[k], bytes):
					si.local_time = FILETIME.from_bytes(ti[k]).datetime
				elif isinstance(ti[k], datetime):
					si.local_time = ti[k]
		
		if challenge.Version is not None:
			si.os_major_version = challenge.Version.ProductMajorVersion
			si.os_minor_version = challenge.Version.ProductMinorVersion
			si.os_build = challenge.Version.ProductBuild
			si.os_guess = challenge.Version.WindowsProduct
				
		return si

	def to_dict(self):
		return {
			'domainname' : self.domainname,
			'computername' : self.computername,
			'dnscomputername' : self.dnscomputername,
			'dnsdomainname' : self.dnsdomainname,
			'local_time' : self.local_time,
			'dnsforestname' : self.dnsforestname,
			'os_major_version' : self.os_major_version.name if self.os_major_version.name is not None else None,
			'os_minor_version' : self.os_minor_version.name if self.os_minor_version.name is not None else None,
			'os_build' : self.os_build,
			'os_guess' : self.os_guess,
		}
		
	def __str__(self):
		t = '=== Server Info ====\r\n'
		for k in self.__dict__:
			t += '%s: %s\r\n' % (k, self.__dict__[k]) 
			
		return t