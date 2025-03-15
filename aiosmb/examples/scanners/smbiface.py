import traceback
from asysocks.unicomm.common.scanner.common import *
from aiosmb.commons.connection.factory import SMBConnectionFactory
from aiosmb.commons.interfaces.machine import SMBMachine


class SMBInterfaceRes:
	def __init__(self, interface):
		self.interface = interface

	def get_header(self):
		return ['interface']

	def to_line(self, separator = '\t'):
		return self.interface
	
	def to_dict(self):
		return {
			'interface' : self.interface
		}

class SMBInterfaceScanner:
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
				ifs, err = await machine.list_interfaces()
				if err is not None:
					raise err
				for iface in ifs:
					await out_queue.put(ScannerData(target, SMBInterfaceRes(iface['address'])))
				
		except Exception as e:
			tb = traceback.format_exc().replace('\n', ' ').replace('\r', '')
			await out_queue.put(ScannerError(target, f"{e} | Traceback: {tb}"))
