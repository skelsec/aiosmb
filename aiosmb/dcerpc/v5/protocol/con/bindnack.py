import io
import enum
from aiosmb.dcerpc.v5.protocol.con.constants import PTYPE, PFC
from aiosmb.dcerpc.v5.protocol.con.commons import PresentationSyntax

class RejectReason(enum.Enum):
	REASON_NOT_SPECIFIED = 0
	TEMPORARY_CONGESTION = 1
	LOCAL_LIMIT_EXCEEDED = 2
	CALLED_PADDR_UNKNOWN = 3
	PROTOCOL_VERSION_NOT_SUPPORTED = 4
	DEFAULT_CONTEXT_NOT_SUPPORTED = 5
	USER_DATA_NOT_READABLE = 6
	NO_PSAP_AVAILABLE = 7

class Version_T:
	def __init__(self):
		self.major = None
		self.minor = None
		
	@staticmethod
	def from_bytes(data):
		return Version_T.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		res = Version_T()
		res.major = int.from_bytes(buff.read(1), byteorder='little', signed=False)
		res.minor  = buff.read(1)
		return res
	
	def __str__(self):
		t = "Version_T: Major: %s Minor: %s" % (self.major, self.minor)
		return t
	
	def __repr__(self):
		return self.__str__()

class RT_Versions_Supported_T:
	def __init__(self):
		self.n_results = None
		self.protocols = []
	
	@staticmethod
	def from_bytes(data):
		return RT_Versions_Supported_T.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		res = RT_Versions_Supported_T()
		res.n_results = int.from_bytes(buff.read(1), byteorder='little', signed=False)
		for _ in range(res.n_results):
			res.protocols.append(Version_T.from_buffer(buff))
		return res
	
	def __str__(self):
		t = "RT_Versions_Supported_T\r\n"
		for entry, i in enumerate(self.protocols):
			t += '%s : %s' % (i, entry)
		return t
	
	def __repr__(self):
		return self.__str__()

class BINDNACKPDU:
	def __init__(self) -> None:
		self.rpc_vers = 5
		self.rpc_vers_minor = 0
		self.PTYPE = PTYPE.BINDNAK
		self.pfc_flags = None
		self.packed_drep = None
		self.frag_length = None
		self.auth_length = None
		self.call_id = None

		self.provider_reject_reason = None
		self.versions = None
		
	
	@staticmethod
	def from_bytes(data):
		return BINDNACKPDU.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		res = BINDNACKPDU()
		res.rpc_vers = int.from_bytes(buff.read(1), byteorder='little', signed=False)
		res.rpc_vers_minor = int.from_bytes(buff.read(1), byteorder='little', signed=False)
		res.PTYPE = PTYPE(int.from_bytes(buff.read(1), byteorder='little', signed=False))
		res.pfc_flags = PFC(int.from_bytes(buff.read(1), byteorder='little', signed=False))
		res.packed_drep = buff.read(4)
		res.frag_length = int.from_bytes(buff.read(2), byteorder='little', signed=False)
		res.auth_length = int.from_bytes(buff.read(2), byteorder='little', signed=False)
		res.call_id = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		res.provider_reject_reason = RejectReason(int.from_bytes(buff.read(2), byteorder='little', signed=False))

		
		return res
	
	def __str__(self):
		t = 'BINDNACKPDU\r\n'
		for k in self.__dict__:
			if isinstance(self.__dict__[k], list):
				for entry, i in enumerate(self.__dict__[k]):
					print(entry)
					t += '%s : %s : %s\r\n' % (k, i, str(entry))
			else:
				t += '%s : %s\r\n' % (k, self.__dict__[k])
		return t
