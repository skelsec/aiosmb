import traceback
from asysocks.unicomm.common.scanner.common import *
from aiosmb.commons.connection.factory import SMBConnectionFactory
from aiosmb.commons.interfaces.machine import SMBMachine
from aiosmb.protocol.common import SMB_NEGOTIATE_PROTOCOL_TEST, NegotiateDialects

class SMBProtocolRes:
	def __init__(self, protores, sign_en, sign_req):
		self.protores = protores.replace('WILDCARD', 'SMB1')
		self.signing_enabled = sign_en
		self.signing_required = sign_req

	def get_header(self):
		return ['PROTO', 'SIGN_ENABLED', 'SIGN_ENFORCED']

	def to_line(self, separator = '\t'):
		return separator.join([str(self.protores), str(self.signing_enabled), str(self.signing_required)])

	def to_dict(self):
		return {
			'PROTO' : self.protores,
			'SIGN_ENABLED' : self.signing_enabled,
			'SIGN_ENFORCED' : self.signing_required
		}

class SMBProtocolScanner:
	def __init__(self, factory:SMBConnectionFactory, protocols = SMB_NEGOTIATE_PROTOCOL_TEST):
		self.factory:SMBConnectionFactory = factory
		self.protocols = protocols
		if isinstance(protocols, dict) is True:
			self.protocols = list(protocols.keys())
		if not isinstance(self.protocols, list):
			self.protocols = [self.protocols]

	async def run(self, targetid, target, out_queue):
		try:
			for protocol in self.protocols:
				connection = self.factory.create_connection_newtarget(target)
				res, sign_en, sign_req, rply, err = await connection.protocol_test([protocol])
				if err is not None:
					raise err
				
				if res is True:
					await out_queue.put(ScannerData(target, SMBProtocolRes(protocol.name, sign_en, sign_req)))
				
		except Exception as e:
			tb = traceback.format_exc().replace('\n', ' ').replace('\r', '')
			await out_queue.put(ScannerError(target, f"{e} | Traceback: {tb}"))
