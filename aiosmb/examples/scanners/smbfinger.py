
import traceback
import asyncio
from asysocks.unicomm.common.scanner.common import *
from aiosmb.commons.connection.factory import SMBConnectionFactory
from asyauth.protocols.ntlm.structures.serverinfo import NTLMSERVERINFO_TSV_HDR, NTLMServerInfo

class SMBFingerRes:
	def __init__(self, res:NTLMServerInfo):
		self.res = res

	def get_header(self):
		return NTLMSERVERINFO_TSV_HDR

	def to_json(self):
		return self.res.to_json()

	def to_line(self, separator = '\t'):
		return self.res.to_tsv(separator)
	
	def to_dict(self):
		return self.res.to_dict()
	

class SMBFingerScanner:
	def __init__(self, factory:SMBConnectionFactory):
		self.factory:SMBConnectionFactory = factory

	async def run(self, targetid, target, out_queue):
		try:
			connection = self.factory.create_connection_newtarget(target)
			res, err = await asyncio.wait_for(connection.fake_login(), timeout = 5)
			if err is not None:
				raise err
			
			await out_queue.put(ScannerData(target, SMBFingerRes(res)))
		except Exception as e:
			tb = traceback.format_exc().replace('\n', ' ').replace('\r', '')
			await out_queue.put(ScannerError(target, f"{e} | Traceback: {tb}"))
