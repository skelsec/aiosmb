import io
import enum
from aiosmb.dcerpc.v5.protocol.con.constants import PTYPE, PFC
from aiosmb.dcerpc.v5.protocol.con.commons import PresentationSyntax


class ResultEnum(enum.Enum):
	ACCEPTANCE = 0
	USER_REJECTION = 1
	PROVIDER_REJECTION = 2

class ProviderReason(enum.Enum):
	REASON_NOT_SPECIFIED = 0
	ABSTRACT_SYNTAX_NOT_SUPPORTED = 1
	PROPOSED_TRANSFER_SYNTAXES_NOT_SUPPORTED = 2
	LOCAL_LIMIT_EXCEEDED = 3

class Result_T:
	def __init__(self):
		self.result = None
		self.reason = None
		self.transfer_syntax = None
	
	@staticmethod
	def from_bytes(data):
		return Result_T.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		res = Result_T()
		res.result = ResultEnum(int.from_bytes(buff.read(2), byteorder='little', signed=False))
		res.reason  = ProviderReason(int.from_bytes(buff.read(2), byteorder='little', signed=False))
		res.transfer_syntax = PresentationSyntax.from_buffer(buff)
		return res
	
	def __str__(self):
		return "Result_T : result: %s reason: %s transfer_syntax: %s" % (self.result, self.reason, self.transfer_syntax)
	
	def __repr__(self):
		return self.__str__()


class Result_List_T:
	def __init__(self):
		self.n_results = None
		self.reserved = None
		self.reserved2 = None
		self.results = []
	
	@staticmethod
	def from_bytes(data):
		return Result_List_T.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		res = Result_List_T()
		res.n_results = int.from_bytes(buff.read(1), byteorder='little', signed=False)
		res.reserved  = buff.read(1)
		res.reserved2 = buff.read(2)
		for _ in range(res.n_results):
			res.results.append(Result_T.from_buffer(buff))
		return res
	
	def __str__(self):
		t = "Result_List_T\r\n"
		for entry, i in enumerate(self.results):
			t += '%s : %s' % (i, entry)
		return t
	
	def __repr__(self):
		return self.__str__()


class PORT_ANY_T:
	def __init__(self):
		self.length = None
		self.port_spec = None #string with null terminator
	
	@staticmethod
	def from_bytes(data):
		return PORT_ANY_T.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		res = PORT_ANY_T()
		res.length = int.from_bytes(buff.read(2), byteorder='little', signed=False)
		res.port_spec = buff.read(res.length).decode('ascii')
		return res
	
	def __str__(self):
		return 'PORT_ANY_T: port_spec: %s' % self.port_spec
	
	def __repr__(self):
		return self.__str__(self)

class BINDACKPDU:
	def __init__(self) -> None:
		self.rpc_vers = 5
		self.rpc_vers_minor = 0
		self.PTYPE = PTYPE.BINDACK
		self.pfc_flags = None
		self.packed_drep = None
		self.frag_length = None
		self.auth_length = None
		self.call_id = None

		self.max_xmit_frag = None
		self.max_recv_frag = None
		self.assoc_group_id = None
		self.sec_addr = None # port_any_t

		#ALIGN(4)
		self.pad2 = None
		self.context_list = None


		self.auth_verifier = None #auth_verifier_co_t
	
	@staticmethod
	def from_bytes(data):
		return BINDACKPDU.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		res = BINDACKPDU()
		res.rpc_vers = int.from_bytes(buff.read(1), byteorder='little', signed=False)
		res.rpc_vers_minor = int.from_bytes(buff.read(1), byteorder='little', signed=False)
		res.PTYPE = PTYPE(int.from_bytes(buff.read(1), byteorder='little', signed=False))
		res.pfc_flags = PFC(int.from_bytes(buff.read(1), byteorder='little', signed=False))
		res.packed_drep = buff.read(4)
		res.frag_length = int.from_bytes(buff.read(2), byteorder='little', signed=False)
		res.auth_length = int.from_bytes(buff.read(2), byteorder='little', signed=False)
		res.call_id = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		res.max_xmit_frag = int.from_bytes(buff.read(2), byteorder='little', signed=False)
		res.max_recv_frag = int.from_bytes(buff.read(2), byteorder='little', signed=False)
		res.assoc_group_id = buff.read(4)
		res.sec_addr = PORT_ANY_T.from_buffer(buff)
		_, padsize = divmod(buff.tell(),4) #ALIGN
		res.pad2 = buff.read(4-padsize)
		res.context_list = Result_List_T.from_buffer(buff)
		
		if res.auth_length > 0:
			res.auth_verifier = buff.read(res.auth_length)
		return res
	
	def __str__(self):
		t = 'BINDACKPDU\r\n'
		for k in self.__dict__:
			if isinstance(self.__dict__[k], list):
				for entry, i in enumerate(self.__dict__[k]):
					print(entry)
					t += '%s : %s : %s\r\n' % (k, i, str(entry))
			else:
				t += '%s : %s\r\n' % (k, self.__dict__[k])
		return t

if __name__ == '__main__':
	data = bytes.fromhex('05000c03100000004400000001000000b810b810126700000d005c504950455c73727673766300000100000000000000045d888aeb1cc9119fe808002b10486002000000')
	x = BINDACKPDU.from_bytes(data)
	print(str(x))