
from asysocks.unicomm.common.scanner.common import *
from aiosmb.commons.connection.factory import SMBConnectionFactory
from aiosmb.commons.interfaces.machine import SMBMachine


class SMBSessionRes:
	def __init__(self, session):
		self.session = session

	def get_header(self):
		return ['USERNAME','IP']

	def to_line(self, separator = '\t'):
		return separator.join([str(self.session.username), str(self.session.ip_addr)])

class SMBSessionScanner:
	def __init__(self, factory:SMBConnectionFactory):
		self.factory:SMBConnectionFactory = factory

	async def run(self, targetid, target, out_queue):
		try:
			connection = self.factory.create_connection_newtarget(target)
			async with connection:
				_, err = await connection.login()
				if err is not None:
					raise err
				
				machine = SMBMachine(connection)
				async for session, err in machine.list_sessions():
					# SMBUserSession
					if err is not None:
						raise err
					await out_queue.put(ScannerData(target, SMBSessionRes(session)))

		except Exception as e:
			await out_queue.put(ScannerError(target, e))
