# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/23e75ca3-98fd-4396-84e5-86cd9d40d343
import enum

class SECURITY_INFORMATION(enum.IntFlag):
	OWNER = 0x00000001 #The owner identifier of the object is being referenced.
	GROUP = 0x00000002 #The primary group identifier of the object is being referenced.
	DACL = 0x00000004 #The DACL of the object is being referenced.
	SACL = 0x00000008 #The SACL of the object is being referenced.
	LABEL = 0x00000010 #The mandatory integrity label is being referenced.
	UNPROTECTED_SACL = 0x10000000 #The SACL inherits access control entries (ACEs) from the parent object.
	UNPROTECTED_DACL = 0x20000000 #The DACL inherits ACEs from the parent object.
	PROTECTED_SACL = 0x40000000 #The SACL cannot inherit ACEs.
	PROTECTED_DACL = 0x80000000 #The DACL cannot inherit ACEs.
	ATTRIBUTE = 0x00000020 #A SYSTEM_RESOURCE_ATTRIBUTE_ACE (section 2.4.4.15) is being referenced.
	SCOPE = 0x00000040 #A SYSTEM_SCOPED_POLICY_ID_ACE (section 2.4.4.16) is being referenced.
	PROCESS_TRUST_LABEL = 0x00000080 #Reserved.
	BACKUP = 0x00010000