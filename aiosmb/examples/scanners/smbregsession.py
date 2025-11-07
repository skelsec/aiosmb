
from asysocks.unicomm.common.scanner.common import *
from aiosmb.commons.connection.factory import SMBConnectionFactory
from aiosmb.commons.interfaces.machine import SMBMachine
from aiosmb.dcerpc.v5.interfaces.remoteregistry import RRPRPC
from aiosmb.dcerpc.v5.interfaces.servicemanager import REMSVCRPC
import traceback
import asyncio

class SMBRegSessionRes:
	def __init__(self, usersid, username = None):
		self.usersid = str(usersid)
		self.username = username

	def get_header(self):
		return ['USERSID']

	def to_line(self, separator = '\t'):
		username = self.username if self.username is not None else ''
		return f'{self.usersid}{separator}{username}'
	
	def to_dict(self):
		return {
			'SID' : self.usersid,
			'USERNAME' : self.username
		}

class SMBRegSessionScanner:
	def __init__(self, factory:SMBConnectionFactory):
		self.factory:SMBConnectionFactory = factory

	async def run(self, targetid, target, out_queue):
		try:
			connection = self.factory.create_connection_newtarget(target)
			async with connection:
				_, err = await connection.login()
				if err is not None:
					raise err
				
				async with SMBMachine(connection) as machine:
					for _ in range(2):
						users, err = await machine.reg_list_users()
						if err is not None:
							await asyncio.sleep(5)
							continue
						if users is not None:
							break
					for user in users:
						user = str(user)
						if user.endswith('_Classes'):
							continue
						if len(user) < 10:
							continue
						
						username, err = await machine.resolve_sid(user)
						# not all SIDs can be resolved
						await out_queue.put(ScannerData(target, SMBRegSessionRes(user, username)))
				
		except Exception as e:
			tb = traceback.format_exc().replace('\n', ' ').replace('\r', '')
			await out_queue.put(ScannerError(target, f"{e} | Traceback: {tb}"))
