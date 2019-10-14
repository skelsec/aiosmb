import io
import enum

from aiosmb.wintypes.dtyp.constrcuted_security.acl import ACL
from aiosmb.wintypes.dtyp.constrcuted_security.sid import SID

class SE_SACL(enum.IntFlag):
	SE_DACL_AUTO_INHERIT_REQ = 0x0100 	#Indicates a required security descriptor in which the discretionary access control list (DACL) is set up to support automatic propagation of inheritable access control entries (ACEs) to existing child objects.
										#For access control lists (ACLs) that support auto inheritance, this bit is always set. Protected servers can call the ConvertToAutoInheritPrivateObjectSecurity function to convert a security descriptor and set this flag.
	SE_DACL_AUTO_INHERITED = 0x0400     #Indicates a security descriptor in which the discretionary access control list (DACL) is set up to support automatic propagation of inheritable access control entries (ACEs) to existing child objects.
										#For access control lists (ACLs) that support auto inheritance, this bit is always set. Protected servers can call the ConvertToAutoInheritPrivateObjectSecurity function to convert a security descriptor and set this flag.
	SE_DACL_DEFAULTED = 0x0008			#Indicates a security descriptor with a default DACL. For example, if the creator an object does not specify a DACL, the object receives the default DACL from the access token of the creator. This flag can affect how the system treats the DACL with respect to ACE inheritance. The system ignores this flag if the SE_DACL_PRESENT flag is not set.
										#This flag is used to determine how the final DACL on the object is to be computed and is not stored physically in the security descriptor control of the securable object.
										#To set this flag, use the SetSecurityDescriptorDacl function.
	SE_DACL_PRESENT = 0x0004			#Indicates a security descriptor that has a DACL. If this flag is not set, or if this flag is set and the DACL is NULL, the security descriptor allows full access to everyone.
										#This flag is used to hold the security information specified by a caller until the security descriptor is associated with a securable object. After the security descriptor is associated with a securable object, the SE_DACL_PRESENT flag is always set in the security descriptor control.
										#To set this flag, use the SetSecurityDescriptorDacl function.
	SE_DACL_PROTECTED = 0x1000			#Prevents the DACL of the security descriptor from being modified by inheritable ACEs. To set this flag, use the SetSecurityDescriptorControl function.
	SE_GROUP_DEFAULTED = 0x0002			#Indicates that the security identifier (SID) of the security descriptor group was provided by a default mechanism. This flag can be used by a resource manager to identify objects whose security descriptor group was set by a default mechanism. To set this flag, use the SetSecurityDescriptorGroup function.
	SE_OWNER_DEFAULTED = 0x0001			#Indicates that the SID of the owner of the security descriptor was provided by a default mechanism. This flag can be used by a resource manager to identify objects whose owner was set by a default mechanism. To set this flag, use the SetSecurityDescriptorOwner function.
	SE_RM_CONTROL_VALID = 0x4000		#Indicates that the resource manager control is valid.
	SE_SACL_AUTO_INHERIT_REQ = 0x0200	#Indicates a required security descriptor in which the system access control list (SACL) is set up to support automatic propagation of inheritable ACEs to existing child objects.
										#The system sets this bit when it performs the automatic inheritance algorithm for the object and its existing child objects. To convert a security descriptor and set this flag, protected servers can call the ConvertToAutoInheritPrivateObjectSecurity function.
	SE_SACL_AUTO_INHERITED = 0x0800		#Indicates a security descriptor in which the system access control list (SACL) is set up to support automatic propagation of inheritable ACEs to existing child objects.
										#The system sets this bit when it performs the automatic inheritance algorithm for the object and its existing child objects. To convert a security descriptor and set this flag, protected servers can call the ConvertToAutoInheritPrivateObjectSecurity function.
	SE_SACL_DEFAULTED = 0x0008			#A default mechanism, rather than the original provider of the security descriptor, provided the SACL. This flag can affect how the system treats the SACL, with respect to ACE inheritance. The system ignores this flag if the SE_SACL_PRESENT flag is not set. To set this flag, use the SetSecurityDescriptorSacl function.
	SE_SACL_PRESENT = 0x0010			#Indicates a security descriptor that has a SACL. To set this flag, use the SetSecurityDescriptorSacl function.
	SE_SACL_PROTECTED = 0x2000			#Prevents the SACL of the security descriptor from being modified by inheritable ACEs. To set this flag, use the SetSecurityDescriptorControl function.
	SE_SELF_RELATIVE = 0x8000			#Indicates a self-relative security descriptor. If this flag is not set, the security descriptor is in absolute format. For more information, see Absolute and Self-Relative Security Descriptors.



#https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_security_descriptor
class SECURITY_DESCRIPTOR:
	def __init__(self):
		self.Revision = None
		self.Sbz1 = None
		self.Control = None
		self.Owner = None
		self.Group = None
		self.Sacl = None
		self.Dacl = None
	
	@staticmethod
	def from_bytes(data):
		return SECURITY_DESCRIPTOR.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		sd = SECURITY_DESCRIPTOR()
		sd.Revision = int.from_bytes(buff.read(1), 'little', signed = False)
		sd.Sbz1 =  int.from_bytes(buff.read(1), 'little', signed = False)
		sd.Control = SE_SACL(int.from_bytes(buff.read(2), 'little', signed = False))
		OffsetOwner  = int.from_bytes(buff.read(4), 'little', signed = False)
		OffsetGroup  = int.from_bytes(buff.read(4), 'little', signed = False)
		OffsetSacl  = int.from_bytes(buff.read(4), 'little', signed = False)
		OffsetDacl  = int.from_bytes(buff.read(4), 'little', signed = False)
		if OffsetOwner > 0:
			buff.seek(OffsetOwner)
			sd.Owner = SID.from_buffer(buff)
		
		if OffsetGroup > 0:
			buff.seek(OffsetGroup)
			sd.Group = SID.from_buffer(buff)
			
		if OffsetSacl > 0:
			buff.seek(OffsetSacl)
			sd.Sacl = ACL.from_buffer(buff)
		
		if OffsetDacl > 0:
			buff.seek(OffsetDacl)
			sd.Dacl = ACL.from_buffer(buff)
			
		return sd
			
			
	def __str__(self):
		t = '=== SECURITY_DESCRIPTOR ==\r\n'
		t+= 'Revision : %s\r\n' % self.Revision
		t+= 'Control : %s\r\n' % self.Control
		t+= 'Owner : %s\r\n' % self.Owner
		t+= 'Group : %s\r\n' % self.Group
		t+= 'Sacl : %s\r\n' % self.Sacl
		t+= 'Dacl : %s\r\n' % self.Dacl
		return t
