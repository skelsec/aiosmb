
from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR
from winacl.dtyp.ace import FILE_ACCESS_MASK
from winacl.functions.rights_calc import EvaluateSidAgainstDescriptor
from typing import List

ORDERED_FIELDS = [
    FILE_ACCESS_MASK.FILE_READ_DATA,
    FILE_ACCESS_MASK.FILE_WRITE_DATA,
    FILE_ACCESS_MASK.FILE_EXECUTE,
	FILE_ACCESS_MASK.FILE_READ_ATTRIBUTES,
    FILE_ACCESS_MASK.FILE_WRITE_ATTRIBUTES,
    FILE_ACCESS_MASK.FILE_APPEND_DATA,
    FILE_ACCESS_MASK.FILE_READ_ATTRIBUTES,
    FILE_ACCESS_MASK.FILE_WRITE_ATTRIBUTES,
    FILE_ACCESS_MASK.FILE_DELETE_CHILD,
]
    
    
    

GENERIC_USER_GROUPS = {
	'S-1-1-0': 'Everyone',
	'S-1-5-11': 'Authenticated Users',
	'S-1-5-32-545' : 'BUILTIN\\Users',
	'S-1-5-32-546' : 'BUILTIN\\Guests',
}

def faccess_basic_check(sd:SECURITY_DESCRIPTOR, user_sid:str = None, user_groups:List[str] = None):
	if sd.Dacl is None:
		# if DACL is None this means everyone has access
		return FILE_ACCESS_MASK.FILE_ALL_ACCESS
	if len(sd.Dacl.aces) == 0:
		# if DACL is empty this means noone has access
		return FILE_ACCESS_MASK(0)
	
	if user_groups is None:
		user_groups = list(GENERIC_USER_GROUPS.keys())
	
	else:
		user_groups.extend(GENERIC_USER_GROUPS.keys())
	
	if user_sid is not None:
		user_groups.append(user_sid)
	has_rights, rights = EvaluateSidAgainstDescriptor(sd, user_sid, 0x02000000, user_groups)
	return FILE_ACCESS_MASK(rights)

def faccess_mask_to_tsv(access:FILE_ACCESS_MASK) -> str:
	return "\t".join(field.name if access & field else "" for field in ORDERED_FIELDS)

def faccess_mask_to_unix(access:FILE_ACCESS_MASK) -> str:
	res = ''
	if FILE_ACCESS_MASK.FILE_READ_DATA in access:
		res += 'r'
	else:
		res += '-'
	if FILE_ACCESS_MASK.FILE_WRITE_DATA in access:
		res += 'w'
	else:
		res += '-'
	if FILE_ACCESS_MASK.FILE_EXECUTE in access:
		res += 'x'
	else:
		res += '-'
	return res

def faccess_match(access, accessfilter):
	accessfilter = accessfilter.lower()
	matches = 0
	if 'r' in accessfilter:
		if FILE_ACCESS_MASK.FILE_READ_DATA in access:
			matches |= FILE_ACCESS_MASK.FILE_READ_DATA
	if 'w' in accessfilter:
		if FILE_ACCESS_MASK.FILE_WRITE_DATA in access:
			matches |= FILE_ACCESS_MASK.FILE_WRITE_DATA
	if 'x' in accessfilter:
		if FILE_ACCESS_MASK.FILE_EXECUTE in access:
			matches |= FILE_ACCESS_MASK.FILE_EXECUTE
	return FILE_ACCESS_MASK(matches)
		