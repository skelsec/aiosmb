import io
from aiosmb.wintypes.dtyp.constrcuted_security.ace import ACEReader

class ACL:
	def __init__(self):
		self.AclRevision = None
		self.Sbz1 = None
		self.AclSize = None
		self.AceCount = None
		self.Sbz2 = None
		
		self.aces = []
		
	@staticmethod
	def from_buffer(buff):
		acl = ACL()
		acl.AclRevision = int.from_bytes(buff.read(1), 'little', signed = False)
		acl.Sbz1 = int.from_bytes(buff.read(1), 'little', signed = False)
		acl.AclSize = int.from_bytes(buff.read(2), 'little', signed = False)
		acl.AceCount = int.from_bytes(buff.read(2), 'little', signed = False)
		acl.Sbz2 = int.from_bytes(buff.read(2), 'little', signed = False)
		for _ in range(acl.AceCount):
			acl.aces.append(ACEReader.from_buffer(buff))
		return acl
		
	def __str__(self):
		t = '=== ACL ===\r\n'
		for ace in self.aces:
			t += '%s\r\n' % str(ace)
		return t