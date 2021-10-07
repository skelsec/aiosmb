import io
import uuid
from aiosmb.dcerpc.v5.protocol.con.constants import PTYPE, PFC
from aiosmb.dcerpc.v5.protocol.con.commons import PresentationSyntax

class Context_Elem_T:
	def __init__(self):
		self.p_cont_id = None
		self.n_transfer_syn = None
		self.reserved = None
		self.abstract_syntax = None
		self.transfer_syntaxes = []
	
	@staticmethod
	def from_bytes(data):
		return Context_Elem_T.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		res = Context_Elem_T()
		res.p_cont_id = int.from_bytes(buff.read(2), byteorder='little', signed=False)
		res.n_transfer_syn  = int.from_bytes(buff.read(1), byteorder='little', signed=False)
		res.reserved = buff.read(1)
		res.abstract_syntax = PresentationSyntax.from_buffer(buff)
		for _ in range(res.n_transfer_syn):
			res.transfer_syntaxes.append(PresentationSyntax.from_buffer(buff))
		return res
	
	def __str__(self):
		t = "Context_Elem_T\r\n"
		t += 'abstract_syntax: %s' % self.abstract_syntax
		for entry, i in enumerate(self.transfer_syntaxes):
			t += '%s : %s' % (i, entry)
		return t
	
	def __repr__(self):
		return self.__str__()
	
class Context_List_T:
	def __init__(self):
		self.n_context_elem = None
		self.reserved = None
		self.reserved2 = None
		self.results = []
	
	@staticmethod
	def from_bytes(data):
		return Context_List_T.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		res = Context_List_T()
		res.n_context_elem = int.from_bytes(buff.read(1), byteorder='little', signed=False)
		res.reserved  = buff.read(1)
		res.reserved2 = buff.read(2)
		for _ in range(res.n_context_elem):
			res.results.append(Context_Elem_T.from_buffer(buff))
		return res
	
	def __str__(self):
		t = "Context_List_T\r\n"
		for entry, i in enumerate(self.results):
			t += '%s : %s' % (i, entry)
		return t
	
	def __repr__(self):
		return self.__str__()


class BINDPDU:
	def __init__(self) -> None:
		self.rpc_vers = 5
		self.rpc_vers_minor = 0
		self.PTYPE = PTYPE.BIND
		self.pfc_flags = None
		self.packed_drep = None
		self.frag_length = None
		self.auth_length = None
		self.call_id = None

		self.max_xmit_frag = None
		self.max_recv_frag = None
		self.assoc_group_id = None
		self.context_list = None #p_cont_list_t p_context_elem; /* variable size */

		self.auth_verifier = None #auth_verifier_co_t
	
	@staticmethod
	def from_bytes(data):
		return BINDPDU.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		res = BINDPDU()
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
		res.context_list = Context_List_T.from_buffer(buff)
		
		if res.auth_length > 0:
			res.auth_verifier = buff.read(res.auth_length)
		return res
	
	def __str__(self):
		t = 'BINDPDU\r\n'
		for k in self.__dict__:
			if isinstance(self.__dict__[k], list):
				for entry, i in enumerate(self.__dict__[k]):
					print(entry)
					t += '%s : %s : %s\r\n' % (k, i, str(entry))
			else:
				t += '%s : %s\r\n' % (k, self.__dict__[k])
		return t

if __name__ == '__main__':
	data = bytes.fromhex('05000b03100000004800000001000000b810b810000000000100000000000100c84f324b7016d30112785a47bf6ee18803000000045d888aeb1cc9119fe808002b10486002000000')
	x = BINDPDU.from_bytes(data)
	print(str(x))