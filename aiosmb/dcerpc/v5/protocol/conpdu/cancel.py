import io
import enum
from aiosmb.dcerpc.v5.protocol.con.constants import PTYPE, PFC

class CANCELPDU:
	def __init__(self) -> None:
		self.rpc_vers = 5
		self.rpc_vers_minor = 0
		self.PTYPE = PTYPE.CO_CANCEL
		self.pfc_flags = None
		self.packed_drep = None
		self.frag_length = None
		self.auth_length = None
		self.call_id = None
		self.auth_verifier = None #auth_verifier_co_t
	
	@staticmethod
	def from_bytes(data):
		return CANCELPDU.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		res = CANCELPDU()
		res.rpc_vers = int.from_bytes(buff.read(1), byteorder='little', signed=False)
		res.rpc_vers_minor = int.from_bytes(buff.read(1), byteorder='little', signed=False)
		res.PTYPE = PTYPE(int.from_bytes(buff.read(1), byteorder='little', signed=False))
		res.pfc_flags = PFC(int.from_bytes(buff.read(1), byteorder='little', signed=False))
		res.packed_drep = buff.read(4)
		res.frag_length = int.from_bytes(buff.read(2), byteorder='little', signed=False)
		res.auth_length = int.from_bytes(buff.read(2), byteorder='little', signed=False)
		res.call_id = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		if res.auth_length > 0:
			res.auth_verifier = buff.read(res.auth_length)
		return res
	
	def __str__(self):
		t = 'CANCELPDU\r\n'
		for k in self.__dict__:
			if isinstance(self.__dict__[k], list):
				for entry, i in enumerate(self.__dict__[k]):
					print(entry)
					t += '%s : %s : %s\r\n' % (k, i, str(entry))
			else:
				t += '%s : %s\r\n' % (k, self.__dict__[k])
		return t
