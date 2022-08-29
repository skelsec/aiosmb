import enum
from aiosmb.commons.interfaces.file import SMBFile
from aiosmb.commons.connection.target import SMBTarget, SMBConnectionDialect
from aiosmb.connection import SMBConnection
from getpass import getpass
import ipaddress
import copy

from asyauth.common.credentials import UniCredential
from asyauth.common.credentials.spnego import SPNEGOCredential

class SMBConnectionFactory:
	def __init__(self, credential:UniCredential = None, target:SMBTarget = None):
		self.credential = credential
		self.target = target
		self.proxies= None
	
	@staticmethod
	def from_url(connection_url):
		target = SMBTarget.from_url(connection_url)
		credential = UniCredential.from_url(connection_url)
		return SMBConnectionFactory(credential, target)

	def get_connection(self):
		spneg = self.get_credential()
		target = self.get_target()
		
		return SMBConnection(spneg, target)

	def create_connection_newtarget(self, ip_or_hostname):
		spneg = self.get_credential()
		#credential.target = ip_or_hostname
		target = self.get_target()

		try:
			ipaddress.ip_address(ip_or_hostname)
			target.ip = ip_or_hostname
			target.hostname = None
		except:
			target.hostname = ip_or_hostname
			target.ip = ip_or_hostname
		
		return SMBConnection(spneg, target)

	def get_file(self):
		return SMBFile.from_smbtarget(self.get_target())

	def get_proxies(self):
		return copy.deepcopy(self.target.proxies)

	def get_target(self):
		return copy.deepcopy(self.target)

	def get_credential(self):
		return SPNEGOCredential([copy.deepcopy(self.credential)]).build_context() 
	
	def __str__(self):
		t = '==== SMBConnectionFactory ====\r\n'
		for k in self.__dict__:
			val = self.__dict__[k]
			if isinstance(val, enum.IntFlag):
				val = val
			elif isinstance(val, enum.Enum):
				val = val.name
			
			t += '%s: %s\r\n' % (k, str(val))
			
		return t
			
if __name__ == '__main__':
	from aiosmb.commons.interfaces.file import SMBFile
	url_tests = [
		'smb://10.10.10.2',
		'smb://10.10.10.2:9000',
		'smb3://10.10.10.2:9000',
		'smb-tcp://10.10.10.2',
		'smb-tcp://10.10.10.2:9000',
		'smb-udp://10.10.10.2:138',
		'smb+ntlm-password://domain\\user@10.10.10.2',
		'smb-tcp+ntlm-password://domain\\user:password@10.10.10.2',
		'smb-tcp+ntlm-password://domain\\user:password@10.10.10.2:10000',
		'smb-tcp+ntlm-nt://domain\\user:alma@10.10.10.2',
		'smb+ntlm-nt://domain\\user:alma@10.10.10.2',
		'smb+ntlm-nt://domain\\user:alma@10.10.10.2',
		'smb-tcp+kerberos-password://domain\\alma:password@10.10.10.10.2',
		'smb-tcp+kerberos-aes://domain\\alma:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@10.10.10.10.2',
		'smb-tcp+kerberos-aes://domain\\alma:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@10.10.10.10.2',
		'smb-tcp+kerberos-nt://domain\\alma:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@10.10.10.10.2',
		'smb-tcp+kerberos-rc4://domain\\alma:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@10.10.10.10.2',
		#'smb+sspi://10.10.10.10.2',
		'smb+sspi-ntlm://10.10.10.10.2',
		'smb+sspi-kerberos://10.10.10.10.2',
		'smb://10.10.10.2/?timeout=10',
		'smb://10.10.10.2/?timeout=10&dc=10.10.10.2',
		'smb://10.10.10.2/?timeout=10&dc=10.10.10.2&proxytype=socks5',
		'smb://10.10.10.2/?timeout=10&dc=10.10.10.2&proxytype=socks5&proxyhost=127.0.0.1',
		'smb://10.10.10.2/?timeout=10&dc=10.10.10.2&proxytype=socks5&proxyhost=127.0.0.1&proxyuser=admin&proxypass=alma',
		'smb://10.10.10.2/?timeout=10&dc=10.10.10.2&proxytype=socks5&proxyhost=127.0.0.1&proxyuser=admin&proxypass=alma&dc=10.10.10.2&dns=8.8.8.8',
		'smb://10.10.10.2/?timeout=10&dc=10.10.10.2&proxytype=socks5s&proxyhost=127.0.0.1&proxyuser=admin&proxypass=alma&dc=10.10.10.2&dns=8.8.8.8',
	]
	for url in url_tests:
		print('===========================================================================')
		print(url)
		try:
			dec = SMBConnectionFactory.from_url(url)
			creds = dec.get_credential()
			target = dec.get_target()
			smbfile = dec.get_file()
			print(smbfile)
		except Exception as e:
			import traceback
			traceback.print_exc()
			print('ERROR! Reason: %s' % e)
			input()
		else:
			print(str(creds))
			print(str(target))
			input()
			
			
