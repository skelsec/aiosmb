
from asysocks.unicomm.common.scanner.common import *
from asysocks.unicomm.common.scanner.targetgen import *
from aiosmb.commons.connection.factory import SMBConnectionFactory
from aiosmb.commons.interfaces.machine import SMBMachine
from asyauth.common.credentials.ntlm import NTLMCredential
from asyauth.common.constants import asyauthSecret, asyauthProtocol, asyauthSubProtocol
from aiosmb.commons.connection.target import SMBTarget
import asyncio
import traceback

class SMBBruteForceRes:
	def __init__(self, domain, username, password):
		self.domain = domain
		self.username = username
		self.password = password

	def get_header(self):
		return ['DOMAIN', 'USERNAME', 'PASSWORD']

	def to_line(self, separator = '\t'):
		return separator.join([str(self.domain), str(self.username), str(self.password)])
	
	def to_dict(self):
		return {
			'DOMAIN' : self.domain,
			'USERNAME' : self.username,
			'PASSWORD' : self.password
		}

class SMBBruteForceScanner:
	def __init__(self, target:SMBTarget, exclude_users):
		self.target = target
		self.exclude_users = exclude_users

	async def run(self, targetid, credtuple, out_queue):
		try:
			domain, username, password = credtuple
			#print('Trying %s\\%s:%s' % (domain, username, password))
			credential = NTLMCredential(password, username, domain, stype = asyauthSecret.PASSWORD)
			connection = SMBConnectionFactory(credential, self.target).get_connection()
			async with connection:
				_, err = await connection.login()
				if err is not None:
					raise err
				
				self.exclude_users[username] = True
				await out_queue.put(ScannerData(self.target.get_hostname_or_ip(), SMBBruteForceRes(domain, username, password)))

		except Exception as e:
			tb = traceback.format_exc().replace('\n', ' ').replace('\r', '')
			await out_queue.put(ScannerError(self.target.get_hostname_or_ip(), f"{e} | Traceback: {tb}"))
