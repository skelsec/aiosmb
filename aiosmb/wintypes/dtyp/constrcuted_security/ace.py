import io
import enum

from aiosmb.wintypes.dtyp.constrcuted_security.sid import SID

#https://docs.microsoft.com/en-us/previous-versions/tn-archive/ff405675(v%3dmsdn.10)
class ADS_ACCESS_MASK(enum.IntFlag):
	CREATE_CHILD   = 0x00000001 #The ObjectType GUID identifies a type of child object. The ACE controls the trustee's right to create this type of child object.
	DELETE_CHILD   = 0x00000002 #The ObjectType GUID identifies a type of child object. The ACE controls the trustee's right to delete this type of child object.
	
	ACTRL_DS_LIST  = 0x00000004
	SELF           = 0x00000008 #The ObjectType GUID identifies a validated write.
	READ_PROP      = 0x00000010 #The ObjectType GUID identifies a property set or property of the object. The ACE controls the trustee's right to read the property or property set.
	WRITE_PROP     = 0x00000020 #The ObjectType GUID identifies a property set or property of the object. The ACE controls the trustee's right to write the property or property set.
	
	DELETE_TREE    = 0x00000040
	LIST_OBJECT    = 0x00000080
	CONTROL_ACCESS = 0x00000100 #The ObjectType GUID identifies an extended access right.
	
	DELETE          = 0x00010000
	READ_CONTROL    = 0x00020000
	WRITE_DACL      = 0x00040000
	WRITE_OWNER     = 0x00080000
	SYNCHRONIZE     = 0x00100000
	
	ACCESS_SYSTEM_SECURITY = 0x01000000
	MAXIMUM_ALLOWED        = 0x02000000
	
	GENERIC_ALL     = 0x10000000
	GENERIC_EXECUTE = 0x20000000
	GENERIC_WRITE   = 0x40000000
	GENERIC_READ    = 0x80000000

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586
class ACEType(enum.Enum):	
	ACCESS_ALLOWED_ACE_TYPE = 0x00
	ACCESS_DENIED_ACE_TYPE = 0x01
	SYSTEM_AUDIT_ACE_TYPE = 0x02
	SYSTEM_ALARM_ACE_TYPE = 0x03
	ACCESS_ALLOWED_COMPOUND_ACE_TYPE = 0x04
	ACCESS_ALLOWED_OBJECT_ACE_TYPE = 0x05
	ACCESS_DENIED_OBJECT_ACE_TYPE = 0x06
	SYSTEM_AUDIT_OBJECT_ACE_TYPE = 0x07
	SYSTEM_ALARM_OBJECT_ACE_TYPE = 0x08
	ACCESS_ALLOWED_CALLBACK_ACE_TYPE = 0x09
	ACCESS_DENIED_CALLBACK_ACE_TYPE = 0x0A
	ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE = 0x0B
	ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE = 0x0C
	SYSTEM_AUDIT_CALLBACK_ACE_TYPE = 0x0D
	SYSTEM_ALARM_CALLBACK_ACE_TYPE = 0x0E
	SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE = 0x0F
	SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE = 0x10 
	SYSTEM_MANDATORY_LABEL_ACE_TYPE = 0x11
	SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE = 0x12
	SYSTEM_SCOPED_POLICY_ID_ACE_TYPE =0x13

class AceFlags(enum.IntFlag):
	CONTAINER_INHERIT_ACE = 0x02
	FAILED_ACCESS_ACE_FLAG = 0x80
	INHERIT_ONLY_ACE = 0x08
	INHERITED_ACE = 0x10
	NO_PROPAGATE_INHERIT_ACE = 0x04
	OBJECT_INHERIT_ACE = 0x01
	SUCCESSFUL_ACCESS_ACE_FLAG = 0x40
	

class ACEReader:
	@staticmethod
	def from_buffer(buff):
		hdr = ACEHeader.pre_parse(buff)
		obj = acetype2ace.get(hdr.AceType)
		if not obj:
			raise Exception('ACE type %s not implemented!' % hdr.AceType)
		return obj.from_buffer(io.BytesIO(buff.read(hdr.AceSize)))

#ACCESS_ALLOWED_ACE	
class ACCESS_ALLOWED_ACE:
	def __init__(self):
		self.Header = None
		self.Mask = None
		self.Sid = None
		
	@staticmethod
	def from_buffer(buff):
		ace = ACCESS_ALLOWED_ACE()
		ace.Header = ACEHeader.from_buffer(buff)
		ace.Mask = ADS_ACCESS_MASK(int.from_bytes(buff.read(4), 'little', signed = False))
		ace.Sid = SID.from_buffer(buff)
		return ace
		
	def __str__(self):
		t = 'ACCESS_ALLOWED_ACE\r\n'
		t += 'Sid: %s\r\n' % self.Sid
		t += 'Mask: %s\r\n' % self.Mask		
		return t
		
class ACCESS_DENIED_ACE:
	def __init__(self):
		self.Header = None
		self.Mask = None
		self.Sid = None
		
	@staticmethod
	def from_buffer(buff):
		ace = ACCESS_DENIED_ACE()
		ace.Header = ACEHeader.from_buffer(buff)
		ace.Mask = ADS_ACCESS_MASK(int.from_bytes(buff.read(4), 'little', signed = False))
		ace.Sid = SID.from_buffer(buff)
		return ace
		
class SYSTEM_AUDIT_ACE:
	def __init__(self):
		self.Header = None
		self.Mask = None
		self.Sid = None
		
	@staticmethod
	def from_buffer(buff):
		ace = SYSTEM_AUDIT_ACE()
		ace.Header = ACEHeader.from_buffer(buff)
		ace.Mask = ADS_ACCESS_MASK(int.from_bytes(buff.read(4), 'little', signed = False))
		ace.Sid = SID.from_buffer(buff)
		return ace
		
class SYSTEM_ALARM_ACE:
	def __init__(self):
		self.Header = None
		self.Mask = None
		self.Sid = None
		
	@staticmethod
	def from_buffer(buff):
		ace = SYSTEM_ALARM_ACE()
		ace.Header = ACEHeader.from_buffer(buff)
		ace.Mask = ADS_ACCESS_MASK(int.from_bytes(buff.read(4), 'little', signed = False))
		ace.Sid = SID.from_buffer(buff)
		return ace
		
#https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c79a383c-2b3f-4655-abe7-dcbb7ce0cfbe
class ACCESS_ALLOWED_OBJECT_Flags(enum.IntFlag):
	NONE = 0x00000000 #Neither ObjectType nor InheritedObjectType are valid.
	ACE_OBJECT_TYPE_PRESENT = 0x00000001 #ObjectType is valid.
	ACE_INHERITED_OBJECT_TYPE_PRESENT = 0x00000002 #InheritedObjectType is valid. If this value is not specified, all types of child objects can inherit the ACE.

class ACCESS_ALLOWED_OBJECT_ACE:
	def __init__(self):
		self.Header = None
		self.Mask = None
		self.Flags = None
		self.ObjectType = None
		self.InheritedObjectType = None
		self.Sid = None
		
	@staticmethod
	def from_buffer(buff):
		ace = ACCESS_ALLOWED_OBJECT_ACE()
		ace.Header = ACEHeader.from_buffer(buff)
		ace.Mask = ADS_ACCESS_MASK(int.from_bytes(buff.read(4), 'little', signed = False))
		ace.Flags = ACCESS_ALLOWED_OBJECT_Flags(int.from_bytes(buff.read(4), 'little', signed = False))
		if ace.Flags & ACCESS_ALLOWED_OBJECT_Flags.ACE_OBJECT_TYPE_PRESENT:
			ace.ObjectType = GUID.from_buffer(buff)
		if ace.Flags & ACCESS_ALLOWED_OBJECT_Flags.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			ace.InheritedObjectType = GUID.from_buffer(buff)
		ace.Sid = SID.from_buffer(buff)
		return ace
		
	def __str__(self):
		t = 'ACCESS_ALLOWED_OBJECT_ACE'
		t += 'ObjectType: %s\r\n' % self.ObjectType
		t += 'InheritedObjectType: %s\r\n' % self.InheritedObjectType
		t += 'ObjectFlags: %s\r\n' % self.Flags
		t += 'AccessControlType: Allow\r\n'
		
		return t
		
class ACCESS_DENIED_OBJECT_ACE:
	def __init__(self):
		self.Header = None
		self.Mask = None
		self.Flags = None
		self.ObjectType = None
		self.InheritedObjectType = None
		self.Sid = None
		
	@staticmethod
	def from_buffer(buff):
		ace = ACCESS_DENIED_OBJECT_ACE()
		ace.Header = ACEHeader.from_buffer(buff)
		ace.Mask = ADS_ACCESS_MASK(int.from_bytes(buff.read(4), 'little', signed = False))
		ace.Flags = ACCESS_ALLOWED_OBJECT_Flags(int.from_bytes(buff.read(4), 'little', signed = False))
		if ace.Flags & ACCESS_ALLOWED_OBJECT_Flags.ACE_OBJECT_TYPE_PRESENT:
			ace.ObjectType = GUID.from_buffer(buff)
		if ace.Flags & ACCESS_ALLOWED_OBJECT_Flags.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			ace.InheritedObjectType = GUID.from_buffer(buff)
		ace.Sid = SID.from_buffer(buff)
		return ace
		
	def __str__(self):
		t = 'ACCESS_DENIED_OBJECT_ACE'
		t += 'ObjectType: %s\r\n' % self.ObjectType
		t += 'InheritedObjectType: %s\r\n' % self.InheritedObjectType
		t += 'ObjectFlags: %s\r\n' % self.Flags
		t += 'AccessControlType: Allow\r\n'
		
		return t
		
class SYSTEM_AUDIT_OBJECT_ACE:
	def __init__(self):
		self.Header = None
		self.Mask = None
		self.Flags = None
		self.ObjectType = None
		self.InheritedObjectType = None
		self.Sid = None
		self.ApplicationData = None
		
	@staticmethod
	def from_buffer(buff):
		ace = SYSTEM_AUDIT_OBJECT_ACE()
		ace.Header = ACEHeader.from_buffer(buff)
		ace.Mask = ADS_ACCESS_MASK(int.from_bytes(buff.read(4), 'little', signed = False))
		ace.Flags = ACCESS_ALLOWED_OBJECT_Flags(int.from_bytes(buff.read(4), 'little', signed = False))
		if ace.Flags & ACCESS_ALLOWED_OBJECT_Flags.ACE_OBJECT_TYPE_PRESENT:
			ace.ObjectType = GUID.from_buffer(buff)
		if ace.Flags & ACCESS_ALLOWED_OBJECT_Flags.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			ace.InheritedObjectType = GUID.from_buffer(buff)
		ace.Sid = SID.from_buffer(buff)
		ace.ApplicationData = buff.read() #not really sure, this will consume the whole buffer! (but we dont know the size at this point!)
		return ace
		
	def __str__(self):
		t = 'SYSTEM_AUDIT_OBJECT_ACE'
		t += 'ObjectType: %s\r\n' % self.ObjectType
		t += 'InheritedObjectType: %s\r\n' % self.InheritedObjectType
		t += 'ObjectFlags: %s\r\n' % self.Flags
		t += 'AccessControlType: Allow\r\n'
		
		return t
		
class ACCESS_ALLOWED_CALLBACK_ACE:
	def __init__(self):
		self.Header = None
		self.Mask = None
		self.Sid = None
		self.ApplicationData = None
		
	@staticmethod
	def from_buffer(buff):
		ace = ACCESS_ALLOWED_CALLBACK_ACE()
		ace.Header = ACEHeader.from_buffer(buff)
		ace.Mask = ADS_ACCESS_MASK(int.from_bytes(buff.read(4), 'little', signed = False))
		ace.Sid = SID.from_buffer(buff)
		ace.ApplicationData = buff.read() #not really sure, this will consume the whole buffer! (but we dont know the size at this point!)
		return ace
		
	def __str__(self):
		t = 'ACCESS_ALLOWED_CALLBACK_ACE'
		t += 'ObjectType: %s\r\n' % self.ObjectType
		t += 'InheritedObjectType: %s\r\n' % self.InheritedObjectType
		t += 'ObjectFlags: %s\r\n' % self.Flags
		t += 'AccessControlType: Allow\r\n'
		
		return t
		
class ACCESS_DENIED_CALLBACK_ACE:
	def __init__(self):
		self.Header = None
		self.Mask = None
		self.Sid = None
		self.ApplicationData = None
		
	@staticmethod
	def from_buffer(buff):
		ace = ACCESS_DENIED_CALLBACK_ACE()
		ace.Header = ACEHeader.from_buffer(buff)
		ace.Mask = ADS_ACCESS_MASK(int.from_bytes(buff.read(4), 'little', signed = False))
		ace.Sid = SID.from_buffer(buff)
		ace.ApplicationData = buff.read() #not really sure, this will consume the whole buffer! (but we dont know the size at this point!)
		return ace
		
	def __str__(self):
		t = 'ACCESS_DENIED_CALLBACK_ACE'
		t += 'ObjectType: %s\r\n' % self.ObjectType
		t += 'InheritedObjectType: %s\r\n' % self.InheritedObjectType
		t += 'ObjectFlags: %s\r\n' % self.Flags
		t += 'AccessControlType: Allow\r\n'
		
		return t
		
class ACCESS_ALLOWED_CALLBACK_OBJECT_ACE:
	def __init__(self):
		self.Header = None
		self.Mask = None
		self.Flags = None
		self.ObjectType = None
		self.InheritedObjectType = None
		self.Sid = None
		self.ApplicationData = None
		
	@staticmethod
	def from_buffer(buff):
		ace = ACCESS_ALLOWED_CALLBACK_OBJECT_ACE()
		ace.Header = ACEHeader.from_buffer(buff)
		ace.Mask = ADS_ACCESS_MASK(int.from_bytes(buff.read(4), 'little', signed = False))
		ace.Flags = ACCESS_ALLOWED_OBJECT_Flags(int.from_bytes(buff.read(4), 'little', signed = False))
		if ace.Flags & ACCESS_ALLOWED_OBJECT_Flags.ACE_OBJECT_TYPE_PRESENT:
			ace.ObjectType = GUID.from_buffer(buff)
		if ace.Flags & ACCESS_ALLOWED_OBJECT_Flags.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			ace.InheritedObjectType = GUID.from_buffer(buff)
		ace.Sid = SID.from_buffer(buff)
		ace.ApplicationData = buff.read() #not really sure, this will consume the whole buffer! (but we dont know the size at this point!)
		return ace
		
	def __str__(self):
		t = 'ACCESS_ALLOWED_CALLBACK_OBJECT_ACE'
		t += 'ObjectType: %s\r\n' % self.ObjectType
		t += 'InheritedObjectType: %s\r\n' % self.InheritedObjectType
		t += 'ObjectFlags: %s\r\n' % self.Flags
		t += 'AccessControlType: Allow\r\n'
		
		return t
		
class ACCESS_DENIED_CALLBACK_OBJECT_ACE:
	def __init__(self):
		self.Header = None
		self.Mask = None
		self.Flags = None
		self.ObjectType = None
		self.InheritedObjectType = None
		self.Sid = None
		self.ApplicationData = None
		
	@staticmethod
	def from_buffer(buff):
		ace = ACCESS_DENIED_CALLBACK_OBJECT_ACE()
		ace.Header = ACEHeader.from_buffer(buff)
		ace.Mask = ADS_ACCESS_MASK(int.from_bytes(buff.read(4), 'little', signed = False))
		ace.Flags = ACCESS_ALLOWED_OBJECT_Flags(int.from_bytes(buff.read(4), 'little', signed = False))
		if ace.Flags & ACCESS_ALLOWED_OBJECT_Flags.ACE_OBJECT_TYPE_PRESENT:
			ace.ObjectType = GUID.from_buffer(buff)
		if ace.Flags & ACCESS_ALLOWED_OBJECT_Flags.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			ace.InheritedObjectType = GUID.from_buffer(buff)
		ace.Sid = SID.from_buffer(buff)
		ace.ApplicationData = buff.read() #not really sure, this will consume the whole buffer! (but we dont know the size at this point!)
		return ace
		
	def __str__(self):
		t = 'ACCESS_DENIED_CALLBACK_OBJECT_ACE'
		t += 'ObjectType: %s\r\n' % self.ObjectType
		t += 'InheritedObjectType: %s\r\n' % self.InheritedObjectType
		t += 'ObjectFlags: %s\r\n' % self.Flags
		t += 'AccessControlType: Allow\r\n'
		
		return t
		
class SYSTEM_AUDIT_CALLBACK_ACE:
	def __init__(self):
		self.Header = None
		self.Mask = None
		self.Sid = None
		self.ApplicationData = None
		
	@staticmethod
	def from_buffer(buff):
		ace = SYSTEM_AUDIT_CALLBACK_ACE()
		ace.Header = ACEHeader.from_buffer(buff)
		ace.Mask = ADS_ACCESS_MASK(int.from_bytes(buff.read(4), 'little', signed = False))
		ace.Sid = SID.from_buffer(buff)
		ace.ApplicationData = buff.read() #not really sure, this will consume the whole buffer! (but we dont know the size at this point!)
		return ace
		
	def __str__(self):
		t = 'SYSTEM_AUDIT_CALLBACK_ACE'
		t += 'ObjectType: %s\r\n' % self.ObjectType
		t += 'InheritedObjectType: %s\r\n' % self.InheritedObjectType
		t += 'ObjectFlags: %s\r\n' % self.Flags
		t += 'AccessControlType: Allow\r\n'
		
		return t
		
class SYSTEM_AUDIT_CALLBACK_OBJECT_ACE:
	def __init__(self):
		self.Header = None
		self.Mask = None
		self.Flags = None
		self.ObjectType = None
		self.InheritedObjectType = None
		self.Sid = None
		self.ApplicationData = None
		
	@staticmethod
	def from_buffer(buff):
		ace = SYSTEM_AUDIT_CALLBACK_OBJECT_ACE()
		ace.Header = ACEHeader.from_buffer(buff)
		ace.Mask = ADS_ACCESS_MASK(int.from_bytes(buff.read(4), 'little', signed = False))
		ace.Flags = ACCESS_ALLOWED_OBJECT_Flags(int.from_bytes(buff.read(4), 'little', signed = False))
		if ace.Flags & ACCESS_ALLOWED_OBJECT_Flags.ACE_OBJECT_TYPE_PRESENT:
			ace.ObjectType = GUID.from_buffer(buff)
		if ace.Flags & ACCESS_ALLOWED_OBJECT_Flags.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			ace.InheritedObjectType = GUID.from_buffer(buff)
		ace.Sid = SID.from_buffer(buff)
		ace.ApplicationData = buff.read() #not really sure, this will consume the whole buffer! (but we dont know the size at this point!)
		return ace
		
	def __str__(self):
		t = 'SYSTEM_AUDIT_CALLBACK_OBJECT_ACE'
		t += 'ObjectType: %s\r\n' % self.ObjectType
		t += 'InheritedObjectType: %s\r\n' % self.InheritedObjectType
		t += 'ObjectFlags: %s\r\n' % self.Flags
		t += 'AccessControlType: Allow\r\n'
		
		return t
		
class SYSTEM_MANDATORY_LABEL_ACE:
	def __init__(self):
		self.Header = None
		self.Mask = None
		self.Sid = None
		
	@staticmethod
	def from_buffer(buff):
		ace = SYSTEM_MANDATORY_LABEL_ACE()
		ace.Header = ACEHeader.from_buffer(buff)
		ace.Mask = ADS_ACCESS_MASK(int.from_bytes(buff.read(4), 'little', signed = False))
		ace.Sid = SID.from_buffer(buff)
		return ace
		
class SYSTEM_RESOURCE_ATTRIBUTE_ACE:
	def __init__(self):
		self.Header = None
		self.Mask = None
		self.Sid = None
		self.AttributeData = None
		

		
	@staticmethod
	def from_buffer(buff):
		ace = SYSTEM_RESOURCE_ATTRIBUTE_ACE()
		ace.Header = ACEHeader.from_buffer(buff)
		ace.Mask = ADS_ACCESS_MASK(int.from_bytes(buff.read(4), 'little', signed = False))
		ace.Sid = SID.from_buffer(buff)
		ace.AttributeData = buff.read() #not really sure, this will consume the whole buffer! (but we dont know the size at this point!)
		return ace
		
	def __str__(self):
		t = 'SYSTEM_RESOURCE_ATTRIBUTE_ACE'
		t += 'ObjectType: %s\r\n' % self.ObjectType
		t += 'InheritedObjectType: %s\r\n' % self.InheritedObjectType
		t += 'ObjectFlags: %s\r\n' % self.Flags
		t += 'AccessControlType: Allow\r\n'
		
		return t
		
class SYSTEM_SCOPED_POLICY_ID_ACE:
	def __init__(self):
		self.Header = None
		self.Mask = None
		self.Sid = None
		
	@staticmethod
	def from_buffer(buff):
		ace = SYSTEM_SCOPED_POLICY_ID_ACE()
		ace.Header = ACEHeader.from_buffer(buff)
		ace.Mask = ADS_ACCESS_MASK(int.from_bytes(buff.read(4), 'little', signed = False))
		ace.Sid = SID.from_buffer(buff)
		return ace
		
acetype2ace = {
	ACEType.ACCESS_ALLOWED_ACE_TYPE : ACCESS_ALLOWED_ACE,
	ACEType.ACCESS_DENIED_ACE_TYPE : ACCESS_DENIED_ACE,
	ACEType.SYSTEM_AUDIT_ACE_TYPE : SYSTEM_AUDIT_ACE,
	ACEType.SYSTEM_ALARM_ACE_TYPE : SYSTEM_ALARM_ACE,
	ACEType.ACCESS_ALLOWED_OBJECT_ACE_TYPE : ACCESS_ALLOWED_OBJECT_ACE,
	ACEType.ACCESS_DENIED_OBJECT_ACE_TYPE : ACCESS_DENIED_OBJECT_ACE,
	ACEType.SYSTEM_AUDIT_OBJECT_ACE_TYPE : SYSTEM_AUDIT_OBJECT_ACE,
	ACEType.ACCESS_ALLOWED_CALLBACK_ACE_TYPE : ACCESS_ALLOWED_CALLBACK_ACE,
	ACEType.ACCESS_DENIED_CALLBACK_ACE_TYPE : ACCESS_DENIED_CALLBACK_ACE,
	ACEType.ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE : ACCESS_ALLOWED_CALLBACK_OBJECT_ACE,
	ACEType.ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE : ACCESS_DENIED_CALLBACK_OBJECT_ACE,
	ACEType.SYSTEM_AUDIT_CALLBACK_ACE_TYPE : SYSTEM_AUDIT_CALLBACK_ACE,
	ACEType.SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE : SYSTEM_AUDIT_CALLBACK_OBJECT_ACE,
	ACEType.SYSTEM_MANDATORY_LABEL_ACE_TYPE : SYSTEM_MANDATORY_LABEL_ACE,
	ACEType.SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE : SYSTEM_RESOURCE_ATTRIBUTE_ACE,
	ACEType.SYSTEM_SCOPED_POLICY_ID_ACE_TYPE : SYSTEM_SCOPED_POLICY_ID_ACE,
	}
"""
ACEType.ACCESS_ALLOWED_COMPOUND_ACE_TYPE : ,# reserved
ACEType.SYSTEM_ALARM_OBJECT_ACE_TYPE : , # reserved
ACEType.SYSTEM_ALARM_CALLBACK_ACE_TYPE : ,# reserved
ACEType.SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE : ,# reserved

"""

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586
class ACEHeader:
	def __init__(self):
		self.AceType = None
		self.AceFlags = None
		self.AceSize = None
		
	@staticmethod
	def from_bytes(data):
		return ACEHeader.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		hdr = ACEHeader()
		hdr.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		hdr.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		hdr.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		return hdr
		
	@staticmethod
	def pre_parse(buff):
		pos = buff.tell()
		hdr = ACEHeader()
		hdr.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		hdr.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		hdr.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		buff.seek(pos,0)
		return hdr


