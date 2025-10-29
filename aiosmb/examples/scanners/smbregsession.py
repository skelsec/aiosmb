
from asysocks.unicomm.common.scanner.common import *
from aiosmb.commons.connection.factory import SMBConnectionFactory
from aiosmb.commons.interfaces.machine import SMBMachine
from aiosmb.dcerpc.v5.interfaces.remoteregistry import RRPRPC
from aiosmb.dcerpc.v5.interfaces.servicemanager import REMSVCRPC
import traceback
import asyncio

class SMBRegSessionRes:
	def __init__(self, usersid):
		self.usersid = str(usersid)

	def get_header(self):
		return ['USERSID']

	def to_line(self, separator = '\t'):
		return separator.join([str(self.usersid)])
	
	def to_dict(self):
		return {
			'USERSID' : self.usersid
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
						await out_queue.put(ScannerData(target, SMBRegSessionRes(user)))
				
		except Exception as e:
			tb = traceback.format_exc().replace('\n', ' ').replace('\r', '')
			await out_queue.put(ScannerError(target, f"{e} | Traceback: {tb}"))
