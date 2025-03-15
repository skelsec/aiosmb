
import traceback
from asysocks.unicomm.common.scanner.common import *
from aiosmb.commons.connection.factory import SMBConnectionFactory
from aiosmb.commons.interfaces.machine import SMBMachine
import os
import asyncio

class SMBPrintnightmareRes:
	def __init__(self, vulntype, is_vuln):
		self.vulntype = vulntype
		self.is_vuln = is_vuln

	def get_header(self):
		return ['VULNTYPE','IS_VULNERABLE']

	def to_line(self, separator = '\t'):
		return separator.join([str(self.vulntype), str(self.is_vuln)])
	
	def to_dict(self):
		return {
			'VULNTYPE' : self.vulntype,
			'IS_VULNERABLE' : self.is_vuln
		}

class SMBPrintnightmareScanner:
	def __init__(self, factory:SMBConnectionFactory):
		self.factory:SMBConnectionFactory = factory

	async def run(self, targetid, target, out_queue):
		try:
			connection = self.factory.create_connection_newtarget(target)
			async with connection:
				_, err = await connection.login()
				if err is not None:
					raise err
				
				nonexistentpath = "C:\\doesntexist\\%s.dll" % os.urandom(4).hex()
				async with SMBMachine(connection) as machine:
					_, err = await asyncio.wait_for(machine.printnightmare(nonexistentpath, None, silent=True), 10)
					if err is not None:
						res = SMBPrintnightmareRes('DIRECT', False)
						if str(err).find('ERROR_PATH_NOT_FOUND') != -1:
							res = SMBPrintnightmareRes('DIRECT', True)
							
						await out_queue.put(ScannerData(target, res))

					_, err = await asyncio.wait_for(machine.par_printnightmare(nonexistentpath, None, silent=True), 10)
					if err is not None:
						res = SMBPrintnightmareRes('PAR', False)
						if str(err).find('ERROR_PATH_NOT_FOUND') != -1:
							res = SMBPrintnightmareRes('PAR', True)
						await out_queue.put(ScannerData(target, res))

		except Exception as e:
			tb = traceback.format_exc().replace('\n', ' ').replace('\r', '')
			await out_queue.put(ScannerError(target, f"{e} | Traceback: {tb}"))
