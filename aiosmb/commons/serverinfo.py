
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
			if challenge.Version.ProductMajorVersion is not None:
				si.os_major_version = challenge.Version.ProductMajorVersion
			if challenge.Version.ProductMinorVersion is not None:
				si.os_minor_version = challenge.Version.ProductMinorVersion
			if challenge.Version.ProductBuild is not None:
				si.os_build = challenge.Version.ProductBuild
			if challenge.Version.WindowsProduct is not None:
				si.os_guess = challenge.Version.WindowsProduct
				
		return si

	def to_dict(self):
		t = {
			'domainname' : self.domainname,
			'computername' : self.computername,
			'dnscomputername' : self.dnscomputername,
			'dnsdomainname' : self.dnsdomainname,
			'local_time' : self.local_time,
			'dnsforestname' : self.dnsforestname,
			'os_build' : self.os_build,
			'os_guess' : self.os_guess,
			'os_major_version' : None,
			'os_minor_version' : None,
		}
		if self.os_major_version is not None:
			t['os_major_version'] = self.os_major_version.name
		if self.os_minor_version is not None:
			t['os_minor_version'] = self.os_minor_version.name
		return t
		
	def __str__(self):
		t = '=== Server Info ====\r\n'
		for k in self.__dict__:
			t += '%s: %s\r\n' % (k, self.__dict__[k]) 
			
		return t

	def to_grep(self):
		t  = ''
		t += '[domainname,%s]' % self.domainname
		t += '[computername,%s]' %  self.computername
		t += '[dnscomputername,%s]' %  self.dnscomputername
		t += '[dnsdomainname,%s]' %  self.dnsdomainname
		t += '[dnsforestname,%s]' %  self.dnsforestname
		t += '[os_build,%s]' %  self.os_build
		t += '[os_guess,%s]' %  self.os_guess
		if self.local_time is not None:
			t += '[local_time,%s]' %  self.local_time.isoformat()
		if self.os_major_version is not None:
			t += '[os_major,%s]' % self.os_major_version.value
		if self.os_minor_version is not None:
			t += '[os_minor,%s]' % self.os_minor_version.value
		
		return t