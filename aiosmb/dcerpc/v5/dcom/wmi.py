# Async WMI (Windows Management Instrumentation) implementation for aiosmb
#
# Based on [MS-WMI]/[MS-WMIO] specifications
# Ported from impacket with async patterns
#
# Provides:
#   - IWbemLevel1Login for WMI namespace login
#   - IWbemServices for WQL queries and method execution
#   - IWbemClassObject for WMI object manipulation
#   - IEnumWbemClassObject for result enumeration
#

from __future__ import division
from struct import unpack, calcsize, pack
from functools import partial
from collections import OrderedDict
import collections
import collections.abc
import logging
import copy
import json

from aiosmb import logger
from aiosmb.dcerpc.v5.dtypes import ULONG, DWORD, LPWSTR, LONG, HRESULT, PGUID, LPCSTR, GUID, NULL
from aiosmb.dcerpc.v5.ndr import NDRSTRUCT, NDRUniConformantArray, NDRPOINTER, \
	NDRUniConformantVaryingArray, NDRUNION, NDRENUM
from aiosmb.dcerpc.v5.rpcrt import DCERPCException
from aiosmb.dcerpc.v5.uuid import string_to_bin, uuidtup_to_bin

from aiosmb.dcerpc.v5.dcom.dcomrt import (
	DCOMCALL, DCOMANSWER, PMInterfacePointer, BYTE_ARRAY,
	PMInterfacePointer_ARRAY, PPMInterfacePointer, OBJREF_CUSTOM, DCOMSessionError,
)
from aiosmb.dcerpc.v5 import hresult_errors
from aiosmb.dcerpc.v5.dcom.oaut import BSTR
from aiosmb.dcerpc.v5.dcom.interface import INTERFACE, CLASS_INSTANCE
from aiosmb.dcerpc.v5.dcom.remunknown import IRemUnknown

from aiosmb.dcerpc.v5.structure import Structure, hexdump

LOG = logger


def checkNullString(string):
	"""Ensure string is null-terminated"""
	if string is None:
		return string
	if string[-1:] != '\x00':
		return string + '\x00'
	return string


def format_structure(d, level=0):
	"""Format a structure for debug output"""
	x = ""
	if isinstance(d, collections.abc.Mapping):
		lenk = max([len(str(x)) for x in list(d.keys())])
		for k, v in list(d.items()):
			key_text = "\n" + " "*level + " "*(lenk - len(str(k))) + str(k)
			x += key_text + ": " + format_structure(v, level=level+lenk)
	elif isinstance(d, collections.abc.Iterable) and not isinstance(d, str):
		for e in d:
			x += "\n" + " "*level + "- " + format_structure(e, level=level+4)
	else:
		x = str(d)
	return x


################################################################################
# CONSTANTS
################################################################################

# WMI CLSIDs and IIDs
CLSID_WbemLevel1Login     = string_to_bin('8BC3F05E-D86B-11D0-A075-00C04FB68820')
CLSID_WbemBackupRestore   = string_to_bin('C49E32C6-BC8B-11D2-85D4-00105A1F8304')
CLSID_WbemClassObject     = string_to_bin('4590F812-1D3A-11D0-891F-00AA004B2E24')

IID_IWbemLevel1Login      = uuidtup_to_bin(('F309AD18-D86A-11d0-A075-00C04FB68820', '0.0'))
IID_IWbemLoginClientID    = uuidtup_to_bin(('d4781cd6-e5d3-44df-ad94-930efe48a887', '0.0'))
IID_IWbemLoginHelper      = uuidtup_to_bin(('541679AB-2E5F-11d3-B34E-00104BCC4B4A', '0.0'))
IID_IWbemServices         = uuidtup_to_bin(('9556DC99-828C-11CF-A37E-00AA003240C7', '0.0'))
IID_IWbemBackupRestore    = uuidtup_to_bin(('C49E32C7-BC8B-11d2-85D4-00105A1F8304', '0.0'))
IID_IWbemBackupRestoreEx  = uuidtup_to_bin(('A359DEC5-E813-4834-8A2A-BA7F1D777D76', '0.0'))
IID_IWbemClassObject      = uuidtup_to_bin(('DC12A681-737F-11CF-884D-00AA004B2E24', '0.0'))
IID_IWbemContext          = uuidtup_to_bin(('44aca674-e8fc-11d0-a07c-00c04fb68820', '0.0'))
IID_IEnumWbemClassObject  = uuidtup_to_bin(('027947e1-d731-11ce-a357-000000000001', '0.0'))
IID_IWbemCallResult       = uuidtup_to_bin(('44aca675-e8fc-11d0-a07c-00c04fb68820', '0.0'))
IID_IWbemFetchSmartEnum   = uuidtup_to_bin(('1C1C45EE-4395-11d2-B60B-00104B703EFD', '0.0'))
IID_IWbemWCOSmartEnum     = uuidtup_to_bin(('423EC01E-2E35-11d2-B604-00104B703EFD', '0.0'))

error_status_t = ULONG

# lFlags constants
WBEM_FLAG_RETURN_WBEM_COMPLETE          = 0x00000000
WBEM_FLAG_UPDATE_ONLY                   = 0x00000001
WBEM_FLAG_CREATE_ONLY                   = 0x00000002
WBEM_FLAG_RETURN_IMMEDIATELY            = 0x00000010
WBEM_FLAG_UPDATE_SAFE_MODE              = 0x00000020
WBEM_FLAG_FORWARD_ONLY                  = 0x00000020
WBEM_FLAG_NO_ERROR_OBJECT               = 0x00000040
WBEM_FLAG_UPDATE_FORCE_MODE             = 0x00000040
WBEM_FLAG_SEND_STATUS                   = 0x00000080
WBEM_FLAG_ENSURE_LOCATABLE              = 0x00000100
WBEM_FLAG_DIRECT_READ                   = 0x00000200
WBEM_MASK_RESERVED_FLAGS                = 0x0001F000
WBEM_FLAG_USE_AMENDED_QUALIFIERS        = 0x00020000
WBEM_FLAG_STRONG_VALIDATION             = 0x00100000
WBEM_FLAG_ADVISORY                      = 0x00010000

# WBEM_INFINITE
WBEM_INFINITE = 0xFFFFFFFF


################################################################################
# WBEM Status Codes
################################################################################

class WBEMSTATUS:
	"""WMI Status Codes (MS-WMI 2.2.11)"""
	WBEM_S_NO_ERROR                      = 0x00000000
	WBEM_S_FALSE                         = 0x00000001
	WBEM_S_TIMEDOUT                      = 0x00040004
	WBEM_S_NEW_STYLE                     = 0x000400FF
	WBEM_S_PARTIAL_RESULTS               = 0x00040010
	WBEM_E_FAILED                        = 0x80041001
	WBEM_E_NOT_FOUND                     = 0x80041002
	WBEM_E_ACCESS_DENIED                 = 0x80041003
	WBEM_E_PROVIDER_FAILURE              = 0x80041004
	WBEM_E_TYPE_MISMATCH                 = 0x80041005
	WBEM_E_OUT_OF_MEMORY                 = 0x80041006
	WBEM_E_INVALID_CONTEXT               = 0x80041007
	WBEM_E_INVALID_PARAMETER             = 0x80041008
	WBEM_E_NOT_AVAILABLE                 = 0x80041009
	WBEM_E_CRITICAL_ERROR                = 0x8004100A
	WBEM_E_NOT_SUPPORTED                 = 0x8004100C
	WBEM_E_PROVIDER_NOT_FOUND            = 0x80041011
	WBEM_E_INVALID_PROVIDER_REGISTRATION = 0x80041012
	WBEM_E_PROVIDER_LOAD_FAILURE         = 0x80041013
	WBEM_E_INITIALIZATION_FAILURE        = 0x80041014
	WBEM_E_TRANSPORT_FAILURE             = 0x80041015
	WBEM_E_INVALID_OPERATION             = 0x80041016
	WBEM_E_ALREADY_EXISTS                = 0x80041019
	WBEM_E_UNEXPECTED                    = 0x8004101D
	WBEM_E_INCOMPLETE_CLASS              = 0x80041020
	WBEM_E_SHUTTING_DOWN                 = 0x80041033
	WBEM_E_INVALID_SUPERCLASS            = 0x8004100D
	WBEM_E_INVALID_NAMESPACE             = 0x8004100E
	WBEM_E_INVALID_OBJECT                = 0x8004100F
	WBEM_E_INVALID_CLASS                 = 0x80041010
	WBEM_E_INVALID_QUERY                 = 0x80041017
	WBEM_E_INVALID_QUERY_TYPE            = 0x80041018
	WBEM_E_PROVIDER_NOT_CAPABLE          = 0x80041024
	WBEM_E_CLASS_HAS_CHILDREN            = 0x80041025
	WBEM_E_CLASS_HAS_INSTANCES           = 0x80041026
	WBEM_E_ILLEGAL_NULL                  = 0x80041028
	WBEM_E_INVALID_CIM_TYPE              = 0x8004102D
	WBEM_E_INVALID_METHOD                = 0x8004102E
	WBEM_E_INVALID_METHOD_PARAMETERS     = 0x8004102F
	WBEM_E_INVALID_PROPERTY              = 0x80041031
	WBEM_E_CALL_CANCELLED                = 0x80041032
	WBEM_E_INVALID_OBJECT_PATH           = 0x8004103A
	WBEM_E_OUT_OF_DISK_SPACE             = 0x8004103B
	WBEM_E_UNSUPPORTED_PUT_EXTENSION     = 0x8004103D
	WBEM_E_QUOTA_VIOLATION               = 0x8004106c
	WBEM_E_SERVER_TOO_BUSY               = 0x80041045
	WBEM_E_METHOD_NOT_IMPLEMENTED        = 0x80041055
	WBEM_E_METHOD_DISABLED               = 0x80041056
	WBEM_E_UNPARSABLE_QUERY              = 0x80041058
	WBEM_E_NOT_EVENT_CLASS               = 0x80041059
	WBEM_E_MISSING_GROUP_WITHIN          = 0x8004105A
	WBEM_E_MISSING_AGGREGATION_LIST      = 0x8004105B
	WBEM_E_PROPERTY_NOT_AN_OBJECT        = 0x8004105c
	WBEM_E_AGGREGATING_BY_OBJECT         = 0x8004105d
	WBEM_E_BACKUP_RESTORE_WINMGMT_RUNNING = 0x80041060
	WBEM_E_QUEUE_OVERFLOW                = 0x80041061
	WBEM_E_PRIVILEGE_NOT_HELD            = 0x80041062
	WBEM_E_INVALID_OPERATOR              = 0x80041063
	WBEM_E_CANNOT_BE_ABSTRACT            = 0x80041065
	WBEM_E_AMENDED_OBJECT                = 0x80041066
	WBEM_E_VETO_PUT                      = 0x8004107A
	WBEM_E_PROVIDER_SUSPENDED            = 0x80041081
	WBEM_E_ENCRYPTED_CONNECTION_REQUIRED = 0x80041087
	WBEM_E_PROVIDER_TIMED_OUT            = 0x80041088
	WBEM_E_NO_KEY                        = 0x80041089
	WBEM_E_PROVIDER_DISABLED             = 0x8004108a
	WBEM_E_REGISTRATION_TOO_BROAD        = 0x80042001
	WBEM_E_REGISTRATION_TOO_PRECISE      = 0x80042002

	@classmethod
	def enumItems(cls, value):
		"""Get status name by value"""
		for name, val in vars(cls).items():
			if not name.startswith('_') and val == value:
				class Result:
					pass
				r = Result()
				r.name = name
				return r
		raise KeyError(f"Unknown status code: 0x{value:08x}")


# Human-readable descriptions for WBEM status codes (MS-WMI / MS-WMIO)
# Maps error code -> (symbolic_name, description)
WBEM_ERROR_MESSAGES = {
	0x00000000: ("WBEM_S_NO_ERROR",                     "Success."),
	0x00000001: ("WBEM_S_FALSE",                        "No more items; enumeration is complete."),
	0x00040004: ("WBEM_S_TIMEDOUT",                     "Operation timed out (partial results may be available)."),
	0x000400FF: ("WBEM_S_NEW_STYLE",                    "Server returned new-style objects."),
	0x00040010: ("WBEM_S_PARTIAL_RESULTS",              "Partial results returned."),
	0x80041001: ("WBEM_E_FAILED",                       "Call failed. Check the WMI provider and class availability."),
	0x80041002: ("WBEM_E_NOT_FOUND",                    "Object or class not found."),
	0x80041003: ("WBEM_E_ACCESS_DENIED",                "Access denied. Current user lacks required WMI permissions."),
	0x80041004: ("WBEM_E_PROVIDER_FAILURE",             "WMI provider encountered an internal error."),
	0x80041005: ("WBEM_E_TYPE_MISMATCH",                "Type mismatch (value type does not match property type)."),
	0x80041006: ("WBEM_E_OUT_OF_MEMORY",                "Server is out of memory."),
	0x80041007: ("WBEM_E_INVALID_CONTEXT",              "The IWbemContext object is not valid."),
	0x80041008: ("WBEM_E_INVALID_PARAMETER",            "One or more parameters are not valid."),
	0x80041009: ("WBEM_E_NOT_AVAILABLE",                "Resource is not available."),
	0x8004100A: ("WBEM_E_CRITICAL_ERROR",               "Internal critical error in WMI."),
	0x8004100C: ("WBEM_E_NOT_SUPPORTED",                "Operation is not supported."),
	0x8004100D: ("WBEM_E_INVALID_SUPERCLASS",           "The specified parent class is not valid."),
	0x8004100E: ("WBEM_E_INVALID_NAMESPACE",            "The specified namespace does not exist (check path like //./root/cimv2)."),
	0x8004100F: ("WBEM_E_INVALID_OBJECT",               "The specified object is not valid."),
	0x80041010: ("WBEM_E_INVALID_CLASS",                "The specified class does not exist."),
	0x80041011: ("WBEM_E_PROVIDER_NOT_FOUND",           "WMI provider for the requested class was not found."),
	0x80041012: ("WBEM_E_INVALID_PROVIDER_REGISTRATION","WMI provider registration is invalid."),
	0x80041013: ("WBEM_E_PROVIDER_LOAD_FAILURE",        "Failed to load WMI provider DLL."),
	0x80041014: ("WBEM_E_INITIALIZATION_FAILURE",       "WMI component initialization failed."),
	0x80041015: ("WBEM_E_TRANSPORT_FAILURE",            "Network transport error."),
	0x80041016: ("WBEM_E_INVALID_OPERATION",            "Operation is not valid in the current state."),
	0x80041017: ("WBEM_E_INVALID_QUERY",                "Query syntax is not valid (check WQL syntax)."),
	0x80041018: ("WBEM_E_INVALID_QUERY_TYPE",           "Requested query language is not supported (use WQL)."),
	0x80041019: ("WBEM_E_ALREADY_EXISTS",               "The class or instance already exists."),
	0x8004101D: ("WBEM_E_UNEXPECTED",                   "Unexpected error from WMI provider."),
	0x80041020: ("WBEM_E_INCOMPLETE_CLASS",             "Class definition is incomplete (missing key or required properties)."),
	0x80041024: ("WBEM_E_PROVIDER_NOT_CAPABLE",         "Provider does not support the requested operation."),
	0x80041025: ("WBEM_E_CLASS_HAS_CHILDREN",           "Cannot delete class that has derived classes."),
	0x80041026: ("WBEM_E_CLASS_HAS_INSTANCES",          "Cannot delete class that has instances."),
	0x80041028: ("WBEM_E_ILLEGAL_NULL",                 "A required property has a NULL value."),
	0x8004102D: ("WBEM_E_INVALID_CIM_TYPE",             "The CIM type specified is not valid."),
	0x8004102E: ("WBEM_E_INVALID_METHOD",               "The requested method does not exist on this class."),
	0x8004102F: ("WBEM_E_INVALID_METHOD_PARAMETERS",    "Method parameters are not valid (wrong count or types)."),
	0x80041031: ("WBEM_E_INVALID_PROPERTY",             "The specified property does not exist on this class."),
	0x80041032: ("WBEM_E_CALL_CANCELLED",               "The operation was cancelled."),
	0x80041033: ("WBEM_E_SHUTTING_DOWN",                "WMI service is shutting down."),
	0x8004103A: ("WBEM_E_INVALID_OBJECT_PATH",          "Object path is not valid (check format: Class.Key=\"Value\")."),
	0x8004103B: ("WBEM_E_OUT_OF_DISK_SPACE",            "Server is out of disk space."),
	0x8004103D: ("WBEM_E_UNSUPPORTED_PUT_EXTENSION",    "The PUT extension is not supported."),
	0x80041045: ("WBEM_E_SERVER_TOO_BUSY",              "WMI server is too busy to process the request."),
	0x80041055: ("WBEM_E_METHOD_NOT_IMPLEMENTED",       "Method is declared but not implemented by the provider."),
	0x80041056: ("WBEM_E_METHOD_DISABLED",              "Method has been disabled by the provider."),
	0x80041058: ("WBEM_E_UNPARSABLE_QUERY",             "Query could not be parsed (check WQL syntax and property names)."),
	0x80041059: ("WBEM_E_NOT_EVENT_CLASS",              "The class is not an event class."),
	0x8004105A: ("WBEM_E_MISSING_GROUP_WITHIN",         "GROUP BY clause requires a WITHIN clause for event queries."),
	0x8004105B: ("WBEM_E_MISSING_AGGREGATION_LIST",     "GROUP BY clause requires an aggregation list."),
	0x8004105C: ("WBEM_E_PROPERTY_NOT_AN_OBJECT",       "Property used with GROUP BY is not an embedded object."),
	0x8004105D: ("WBEM_E_AGGREGATING_BY_OBJECT",        "Cannot aggregate on an embedded object property."),
	0x80041060: ("WBEM_E_BACKUP_RESTORE_WINMGMT_RUNNING","Cannot perform backup/restore while WMI service is running."),
	0x80041061: ("WBEM_E_QUEUE_OVERFLOW",               "Asynchronous delivery queue overflowed."),
	0x80041062: ("WBEM_E_PRIVILEGE_NOT_HELD",           "Required privilege is not held by the caller."),
	0x80041063: ("WBEM_E_INVALID_OPERATOR",             "Invalid operator used in the WHERE clause."),
	0x80041065: ("WBEM_E_CANNOT_BE_ABSTRACT",           "Class cannot be marked as abstract."),
	0x80041066: ("WBEM_E_AMENDED_OBJECT",               "An amended object was used in a PUT operation."),
	0x8004106C: ("WBEM_E_QUOTA_VIOLATION",              "WMI quota has been exceeded (too many connections or objects)."),
	0x8004107A: ("WBEM_E_VETO_PUT",                     "The provider vetoed the PUT/create operation."),
	0x80041081: ("WBEM_E_PROVIDER_SUSPENDED",           "WMI provider is suspended."),
	0x80041087: ("WBEM_E_ENCRYPTED_CONNECTION_REQUIRED", "An encrypted (privacy-level) connection is required. Set auth_level to RPC_C_AUTHN_LEVEL_PKT_PRIVACY."),
	0x80041088: ("WBEM_E_PROVIDER_TIMED_OUT",           "WMI provider timed out while processing the request."),
	0x80041089: ("WBEM_E_NO_KEY",                       "Cannot complete PUT operation: class has no key property defined."),
	0x8004108A: ("WBEM_E_PROVIDER_DISABLED",            "WMI provider is disabled."),
	0x80042001: ("WBEM_E_REGISTRATION_TOO_BROAD",       "Event subscription filter is too broad."),
	0x80042002: ("WBEM_E_REGISTRATION_TOO_PRECISE",     "Event subscription filter is too precise."),
}


class WMISessionError(DCOMSessionError):
	"""
	WMI-specific session error with human-readable WBEM status messages.
	
	Translates WBEM error codes (0x8004xxxx) into their symbolic names
	and descriptions, so you see:
	    WMI SessionError: code: 0x80041010 - WBEM_E_INVALID_CLASS - The specified class does not exist.
	instead of:
	    DCOM SessionError: unknown error code: 0x80041010
	"""
	def __init__(self, error_string=None, error_code=None, packet=None):
		super().__init__(error_string, error_code, packet)
	
	def __str__(self):
		if self.error_string is not None:
			return self.error_string
		if self.error_code is not None:
			if self.error_code in WBEM_ERROR_MESSAGES:
				name, desc = WBEM_ERROR_MESSAGES[self.error_code]
				return 'WMI SessionError: code: 0x%08x - %s - %s' % (self.error_code, name, desc)
			# Fall back to the hresult_errors table (covers general COM/DCOM errors)
			if self.error_code in hresult_errors.ERROR_MESSAGES:
				error_msg_short = hresult_errors.ERROR_MESSAGES[self.error_code][0]
				error_msg_verbose = hresult_errors.ERROR_MESSAGES[self.error_code][1]
				return 'WMI SessionError: code: 0x%08x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
			return 'WMI SessionError: unknown error code: 0x%08x' % self.error_code
		return super().__str__()


# Override DCERPCSessionError so the DCE/RPC transport layer creates
# WMISessionError (with WBEM code translation) instead of generic DCOMSessionError
# for all errors originating from WMI RPC calls.
DCERPCSessionError = WMISessionError


################################################################################
# WMIO Structures and Constants
################################################################################

WBEM_FLAVOR_FLAG_PROPAGATE_O_INSTANCE      = 0x01
WBEM_FLAVOR_FLAG_PROPAGATE_O_DERIVED_CLASS = 0x02
WBEM_FLAVOR_NOT_OVERRIDABLE                = 0x10
WBEM_FLAVOR_ORIGIN_PROPAGATED              = 0x20
WBEM_FLAVOR_ORIGIN_SYSTEM                  = 0x40
WBEM_FLAVOR_AMENDED                        = 0x80

# 2.2.6 ObjectFlags
OBJECT_FLAGS = 'B=0'

# 2.2.77 Signature
SIGNATURE = '<L=0x12345678'

# 2.2.4 ObjectEncodingLength
OBJECT_ENCODING_LENGTH = '<L=0'

# 2.2.73 EncodingLength
ENCODING_LENGTH = '<L=0'

# 2.2.78 Encoded-String
ENCODED_STRING_FLAG = 'B=0'

# 2.2.76 ReservedOctet
RESERVED_OCTET = 'B=0'

# 2.2.65 HeapRef
HEAPREF = '<L=0'

# 2.2.68 HeapStringRef
HEAP_STRING_REF = HEAPREF

# 2.2.67 DictionaryReference
DICTIONARY_REFERENCE = {
	0: b'',
	1: b'key',
	2: b'CYCLEGROUP',
	3: b'Description',
	4: b'Read',
	5: b'Write',
	6: b'Volatile',
	7: b'Provider',
	8: b'Dynamic',
	9: b'DYNPROPS',
	10: b'Type',
	11: b'ClassContext',
	12: b'Class',
	13: b'Singleton',
	14: b'CIMTYPE',
	15: b'PropertyContext',
	16: b'Amendment',
	17: b'ID',
	18: b'Abstract',
	19: b'Locale',
	20: b'in',
	21: b'out',
	22: b'Optional',
	23: b'Required',
	24: b'Not_Null',
	25: b'ValueMap',
	26: b'Values',
	27: b'Bypass_GetObject',
	28: b'ClassRef',
	29: b'EmbeddedInstance',
	30: b'MappingStrings',
	31: b'Override',
	32: b'static',
}

# 2.2.61 QualifierName
QUALIFIER_NAME = HEAP_STRING_REF

# 2.2.62 QualifierFlavor
QUALIFIER_FLAVOR = 'B=0'

# 2.2.63 QualifierType
QUALIFIER_TYPE = '<L=0'

# Property flag
Inherited = 0x4000


class CIM_TYPE_ENUM:
	"""CIM Type enumeration"""
	CIM_TYPE_SINT8      = 16
	CIM_TYPE_UINT8      = 17
	CIM_TYPE_SINT16     = 2
	CIM_TYPE_UINT16     = 18
	CIM_TYPE_SINT32     = 3
	CIM_TYPE_UINT32     = 19
	CIM_TYPE_SINT64     = 20
	CIM_TYPE_UINT64     = 21
	CIM_TYPE_REAL32     = 4
	CIM_TYPE_REAL64     = 5
	CIM_TYPE_BOOLEAN    = 11
	CIM_TYPE_STRING     = 8
	CIM_TYPE_DATETIME   = 101
	CIM_TYPE_REFERENCE  = 102
	CIM_TYPE_CHAR16     = 103
	CIM_TYPE_OBJECT     = 13
	CIM_ARRAY_SINT8     = 8208
	CIM_ARRAY_UINT8     = 8209
	CIM_ARRAY_SINT16    = 8194
	CIM_ARRAY_UINT16    = 8210
	CIM_ARRAY_SINT32    = 8195
	CIM_ARRAY_UINT32    = 8211
	CIM_ARRAY_SINT64    = 8212
	CIM_ARRAY_UINT64    = 8213
	CIM_ARRAY_REAL32    = 8196
	CIM_ARRAY_REAL64    = 8197
	CIM_ARRAY_BOOLEAN   = 8203
	CIM_ARRAY_STRING    = 8200
	CIM_ARRAY_DATETIME  = 8293
	CIM_ARRAY_REFERENCE = 8294
	CIM_ARRAY_CHAR16    = 8295
	CIM_ARRAY_OBJECT    = 8205


CIM_ARRAY_FLAG = 0x2000

CIM_TYPES_REF = {
	CIM_TYPE_ENUM.CIM_TYPE_SINT8    : 'b=0',
	CIM_TYPE_ENUM.CIM_TYPE_UINT8    : 'B=0',
	CIM_TYPE_ENUM.CIM_TYPE_SINT16   : '<h=0',
	CIM_TYPE_ENUM.CIM_TYPE_UINT16   : '<H=0',
	CIM_TYPE_ENUM.CIM_TYPE_SINT32   : '<l=0',
	CIM_TYPE_ENUM.CIM_TYPE_UINT32   : '<L=0',
	CIM_TYPE_ENUM.CIM_TYPE_SINT64   : '<q=0',
	CIM_TYPE_ENUM.CIM_TYPE_UINT64   : '<Q=0',
	CIM_TYPE_ENUM.CIM_TYPE_REAL32   : '<f=0',
	CIM_TYPE_ENUM.CIM_TYPE_REAL64   : '<d=0',
	CIM_TYPE_ENUM.CIM_TYPE_BOOLEAN  : '<H=0',
	CIM_TYPE_ENUM.CIM_TYPE_STRING   : HEAPREF,
	CIM_TYPE_ENUM.CIM_TYPE_DATETIME : HEAPREF,
	CIM_TYPE_ENUM.CIM_TYPE_REFERENCE: HEAPREF,
	CIM_TYPE_ENUM.CIM_TYPE_CHAR16   : '<H=0',
	CIM_TYPE_ENUM.CIM_TYPE_OBJECT   : HEAPREF,
}

CIM_TYPE_TO_NAME = {
	CIM_TYPE_ENUM.CIM_TYPE_SINT8    : 'sint8',
	CIM_TYPE_ENUM.CIM_TYPE_UINT8    : 'uint8',
	CIM_TYPE_ENUM.CIM_TYPE_SINT16   : 'sint16',
	CIM_TYPE_ENUM.CIM_TYPE_UINT16   : 'uint16',
	CIM_TYPE_ENUM.CIM_TYPE_SINT32   : 'sint32',
	CIM_TYPE_ENUM.CIM_TYPE_UINT32   : 'uint32',
	CIM_TYPE_ENUM.CIM_TYPE_SINT64   : 'sint64',
	CIM_TYPE_ENUM.CIM_TYPE_UINT64   : 'uint64',
	CIM_TYPE_ENUM.CIM_TYPE_REAL32   : 'real32',
	CIM_TYPE_ENUM.CIM_TYPE_REAL64   : 'real64',
	CIM_TYPE_ENUM.CIM_TYPE_BOOLEAN  : 'bool',
	CIM_TYPE_ENUM.CIM_TYPE_STRING   : 'string',
	CIM_TYPE_ENUM.CIM_TYPE_DATETIME : 'datetime',
	CIM_TYPE_ENUM.CIM_TYPE_REFERENCE: 'reference',
	CIM_TYPE_ENUM.CIM_TYPE_CHAR16   : 'char16',
	CIM_TYPE_ENUM.CIM_TYPE_OBJECT   : 'object',
}

CIM_NUMBER_TYPES = {
	CIM_TYPE_ENUM.CIM_TYPE_SINT8,
	CIM_TYPE_ENUM.CIM_TYPE_UINT8,
	CIM_TYPE_ENUM.CIM_TYPE_SINT16,
	CIM_TYPE_ENUM.CIM_TYPE_UINT16,
	CIM_TYPE_ENUM.CIM_TYPE_SINT32,
	CIM_TYPE_ENUM.CIM_TYPE_UINT32,
	CIM_TYPE_ENUM.CIM_TYPE_SINT64,
	CIM_TYPE_ENUM.CIM_TYPE_UINT64,
	CIM_TYPE_ENUM.CIM_TYPE_REAL32,
	CIM_TYPE_ENUM.CIM_TYPE_REAL64,
}


################################################################################
# ENCODED_STRING and ENCODED_VALUE
################################################################################

class ENCODED_STRING(Structure):
	"""2.2.78 Encoded-String"""
	
	commonHdr = (
		('Encoded_String_Flag', ENCODED_STRING_FLAG),
	)
	
	tascii = (
		('Character', 'z'),  # null-terminated ASCII string
	)
	
	tunicode = (
		('Character', 'u'),  # null-terminated Unicode string
	)
	
	def __init__(self, data=None, alignment=0):
		Structure.__init__(self, data, alignment)
		self.structure = ()
		self.isUnicode = False
		if data is not None:
			# First parse the flag
			self.fromString(data)
			if len(data) > 1:
				if self['Encoded_String_Flag'] == 0:
					self.structure += self.tascii
					# Find the end of the ASCII string (null terminator)
					index = data[1:].find(b'\x00')
					data = data[:index+1+1]  # flag + string + null
				else:
					self.structure += self.tunicode
					self.isUnicode = True
				self.fromString(data)
		else:
			self.structure = self.tascii
			self.data = None
	
	def __getitem__(self, key):
		if key == 'Character' and self.isUnicode:
			return self.fields['Character'].decode('utf-16le')
		return Structure.__getitem__(self, key)


class ENCODED_VALUE:
	"""Helper class for encoding/decoding CIM values"""
	
	@staticmethod
	def getValue(cimType, entry, heap):
		"""Decode a value from the heap"""
		# Get the base type without array flag and inherited flag
		pType = cimType & (~(CIM_ARRAY_FLAG | Inherited))
		cimType = cimType & (~Inherited)
		
		# Check for null/invalid entry - 0xffffffff means no value
		if entry != 0xffffffff:
			heapData = heap[entry:]
			
			if cimType & CIM_ARRAY_FLAG:
				# Array type - get the count first
				dataSize = calcsize(HEAPREF[:-2])
				numItems = unpack(HEAPREF[:-2], heapData[:dataSize])[0]
				heapData = heapData[dataSize:]
				array = []
				
				unpackStrArray = CIM_TYPES_REF[pType][:-2]
				dataSizeArray = calcsize(unpackStrArray)
				
				if cimType == CIM_TYPE_ENUM.CIM_ARRAY_STRING:
					# Array of strings - read heap offsets and resolve each string from full heap
					# The offsets point to absolute positions in the heap
					for i in range(numItems):
						strOffset = unpack('<I', heapData[i*4:(i+1)*4])[0]
						if strOffset != 0xffffffff and strOffset < len(heap):
							item = ENCODED_STRING(heap[strOffset:])
							array.append(item['Character'])
						else:
							array.append(None)
				elif cimType == CIM_TYPE_ENUM.CIM_ARRAY_OBJECT:
					# Array of objects - discard pointers first
					heapData = heapData[dataSizeArray*numItems:]
					for _ in range(numItems):
						msb = METHOD_SIGNATURE_BLOCK(heapData)
						unit = ENCODING_UNIT()
						unit['ObjectEncodingLength'] = msb['EncodingLength']
						unit['ObjectBlock'] = msb['ObjectBlock']
						array.append(unit)
						heapData = heapData[msb['EncodingLength']+4:]
				else:
					for _ in range(numItems):
						array.append(unpack(unpackStrArray, heapData[:dataSizeArray])[0])
						heapData = heapData[dataSizeArray:]
				value = array
				
			elif pType == CIM_TYPE_ENUM.CIM_TYPE_BOOLEAN:
				if entry == 0xffff:
					value = 'True'
				else:
					value = 'False'
					
			elif pType == CIM_TYPE_ENUM.CIM_TYPE_OBJECT:
				msb = METHOD_SIGNATURE_BLOCK(heapData)
				unit = ENCODING_UNIT()
				unit['ObjectEncodingLength'] = msb['EncodingLength']
				unit['ObjectBlock'] = msb['ObjectBlock']
				value = unit
				
			elif pType not in (CIM_TYPE_ENUM.CIM_TYPE_STRING,
							  CIM_TYPE_ENUM.CIM_TYPE_DATETIME,
							  CIM_TYPE_ENUM.CIM_TYPE_REFERENCE):
				value = entry
			else:
				try:
					value = ENCODED_STRING(heapData)['Character']
				except UnicodeDecodeError:
					if logging.getLogger().level == logging.DEBUG:
						LOG.debug('Unicode Error: dumping heapData')
						hexdump(heapData)
					raise
			
			return value
		
		# entry == 0xffffffff means null/no value
		return None


################################################################################
# WMIO Object Structures
################################################################################

# 2.2.64 QualifierValue
QUALIFIER_VALUE = HEAPREF


class QUALIFIER(Structure):
	"""2.2.60 Qualifier"""
	commonHdr = (
		('QualifierName', QUALIFIER_NAME),
		('QualifierFlavor', QUALIFIER_FLAVOR),
		('QualifierType', QUALIFIER_TYPE),
	)
	
	def __init__(self, data=None, alignment=0):
		Structure.__init__(self, data, alignment)
		if data is not None:
			self.fromString(data)
			# Mask out both CIM_ARRAY_FLAG and Inherited flag to get base type
			baseType = self["QualifierType"] & (~CIM_ARRAY_FLAG) & (~Inherited)
			self.structure = (
				('QualifierValue', CIM_TYPES_REF[baseType]),
			)
			self.fromString(data)
		else:
			self.data = None


class QUALIFIER_SET(Structure):
	"""2.2.59 QualifierSet"""
	structure = (
		('EncodingLength', ENCODING_LENGTH),
		('_Qualifier','_-Qualifier', 'self["EncodingLength"]-4'),
		('Qualifier', ':'),
	)
	
	def getQualifiers(self, heap):
		data = self['Qualifier']
		qualifiers = dict()
		while len(data) > 0:
			itemn = QUALIFIER(data)
			if itemn['QualifierName'] == 0xffffffff:
				qName = b''
			elif itemn['QualifierName'] & 0x80000000:
				qName = DICTIONARY_REFERENCE[itemn['QualifierName'] & 0x7fffffff]
			else:
				qName = ENCODED_STRING(heap[itemn['QualifierName']:])['Character']
			
			value = ENCODED_VALUE.getValue(
				itemn['QualifierType'],
				itemn['QualifierValue'],
				heap
			)
			qualifiers[qName] = value
			data = data[len(itemn):]
		return qualifiers


# 2.2.20 ClassQualifierSet
CLASS_QUALIFIER_SET = QUALIFIER_SET

# 2.2.22 PropertyCount
PROPERTY_COUNT = '<L=0'

# 2.2.24 PropertyNameRef
PROPERTY_NAME_REF = HEAP_STRING_REF

# 2.2.25 PropertyInfoRef
PROPERTY_INFO_REF = HEAPREF


class PropertyLookup(Structure):
	"""2.2.23 PropertyLookup"""
	structure = (
		('PropertyNameRef', PROPERTY_NAME_REF),
		('PropertyInfoRef', PROPERTY_INFO_REF),
	)


# 2.2.31 PropertyType
PROPERTY_TYPE = '<L=0'

# 2.2.33 DeclarationOrder
DECLARATION_ORDER = '<H=0'

# 2.2.34 ValueTableOffset
VALUE_TABLE_OFFSET = '<L=0'

# 2.2.35 ClassOfOrigin
CLASS_OF_ORIGIN = '<L=0'

# 2.2.36 PropertyQualifierSet
PROPERTY_QUALIFIER_SET = QUALIFIER_SET


class PROPERTY_INFO(Structure):
	"""2.2.30 PropertyInfo"""
	structure = (
		('PropertyType', PROPERTY_TYPE),
		('DeclarationOrder', DECLARATION_ORDER),
		('ValueTableOffset', VALUE_TABLE_OFFSET),
		('ClassOfOrigin', CLASS_OF_ORIGIN),
		('PropertyQualifierSet', ':', PROPERTY_QUALIFIER_SET),
	)


class PROPERTY_LOOKUP_TABLE(Structure):
	"""2.2.21 PropertyLookupTable"""
	PropertyLookupSize = 8
	
	structure = (
		('PropertyCount', PROPERTY_COUNT),
		('_PropertyLookup', '_-PropertyLookup', 
		 'self["PropertyCount"]*self.PropertyLookupSize'),
		('PropertyLookup', ':'),
	)
	
	def getProperties(self, heap):
		propTable = self['PropertyLookup']
		properties = dict()
		
		for _ in range(self['PropertyCount']):
			propItemDict = dict()
			propItem = PropertyLookup(propTable)
			
			if propItem['PropertyNameRef'] & 0x80000000:
				propName = DICTIONARY_REFERENCE[propItem['PropertyNameRef'] & 0x7fffffff]
			else:
				propName = ENCODED_STRING(heap[propItem['PropertyNameRef']:])['Character']
			
			propInfo = PROPERTY_INFO(heap[propItem['PropertyInfoRef']:])
			pType = propInfo['PropertyType']
			pType &= (~CIM_ARRAY_FLAG)
			pType &= (~Inherited)
			sType = CIM_TYPE_TO_NAME.get(pType, 'unknown')
			
			propItemDict['stype'] = sType
			propItemDict['name'] = propName
			propItemDict['type'] = propInfo['PropertyType']
			propItemDict['order'] = propInfo['DeclarationOrder']
			propItemDict['inherited'] = propInfo['PropertyType'] & Inherited
			propItemDict['value'] = None
			
			# Get qualifiers
			qualifiers = dict()
			qualifiersBuf = propInfo['PropertyQualifierSet']['Qualifier']
			while len(qualifiersBuf) > 0:
				record = QUALIFIER(qualifiersBuf)
				if record['QualifierName'] & 0x80000000:
					qualifierName = DICTIONARY_REFERENCE[record['QualifierName'] & 0x7fffffff]
				else:
					qualifierName = ENCODED_STRING(heap[record['QualifierName']:])['Character']
				qualifierValue = ENCODED_VALUE.getValue(
					record['QualifierType'],
					record['QualifierValue'],
					heap
				)
				qualifiersBuf = qualifiersBuf[len(record):]
				qualifiers[qualifierName] = qualifierValue
			
			propItemDict['qualifiers'] = qualifiers
			properties[propName] = propItemDict
			propTable = propTable[self.PropertyLookupSize:]
		
		return OrderedDict(sorted(list(properties.items()), key=lambda x: x[1]['order']))


# 2.2.66 Heap
HEAP_LENGTH = '<L=0'


class HEAP(Structure):
	"""2.2.66 Heap"""
	structure = (
		('HeapLength', HEAP_LENGTH),
		('_HeapItem', '_-HeapItem', 'self["HeapLength"]&0x7fffffff'),
		('HeapItem', ':'),
	)


# 2.2.37 ClassHeap
CLASS_HEAP = HEAP


class CLASS_HEADER(Structure):
	"""2.2.9 ClassHeader"""
	structure = (
		('EncodingLength', '<L=0'),
		('ReservedOctet', 'B=0'),
		('ClassNameRef', HEAP_STRING_REF),
		('NdTableValueTableLength', '<L=0'),
	)


class DERIVATION_LIST(Structure):
	"""2.2.16 DerivationList"""
	structure = (
		('EncodingLength', ENCODING_LENGTH),
		('_ClassNameEncoding', '_-ClassNameEncoding', 'self["EncodingLength"]-4'),
		('ClassNameEncoding', ':'),
	)


class CLASS_PART(Structure):
	"""2.2.15 ClassPart"""
	commonHdr = (
		('ClassHeader', ':', CLASS_HEADER),
		('DerivationList', ':', DERIVATION_LIST),
		('ClassQualifierSet', ':', CLASS_QUALIFIER_SET),
		('PropertyLookupTable', ':', PROPERTY_LOOKUP_TABLE),
		('_NdTable_ValueTable', '_-NdTable_ValueTable', 
		 'self["ClassHeader"]["NdTableValueTableLength"]'),
		('NdTable_ValueTable', ':'),
		('ClassHeap', ':', CLASS_HEAP),
		('_Garbage', '_-Garbage', 
		 'self["ClassHeader"]["EncodingLength"]-len(self)'),
		('Garbage', ':=b""'),
	)
	
	def getQualifiers(self):
		return self["ClassQualifierSet"].getQualifiers(self["ClassHeap"]["HeapItem"])
	
	def getProperties(self):
		heap = self["ClassHeap"]["HeapItem"]
		properties = self["PropertyLookupTable"].getProperties(heap)
		sorted_props = sorted(list(properties.keys()), key=lambda k: properties[k]['order'])
		
		valueTableOff = (len(properties) - 1) // 4 + 1
		valueTable = self['NdTable_ValueTable'][valueTableOff:]
		
		for key in sorted_props:
			pType = properties[key]['type'] & (~(CIM_ARRAY_FLAG | Inherited))
			if properties[key]['type'] & CIM_ARRAY_FLAG:
				unpackStr = HEAPREF[:-2]
			else:
				unpackStr = CIM_TYPES_REF[pType][:-2]
			dataSize = calcsize(unpackStr)
			
			try:
				itemValue = unpack(unpackStr, valueTable[:dataSize])[0]
			except:
				LOG.error("getProperties: Error unpacking!!")
				itemValue = 0xffffffff
			
			if itemValue != 0xffffffff and itemValue > 0:
				value = ENCODED_VALUE.getValue(properties[key]['type'], itemValue, heap)
				properties[key]['value'] = "%s" % value
			
			valueTable = valueTable[dataSize:]
		
		return properties


# Method structures
METHOD_COUNT = '<H=0'
METHOD_COUNT_PADDING = '<H=0'
METHOD_NAME = HEAP_STRING_REF
METHOD_FLAGS = 'B=0'
METHOD_PADDING = "3s=b''"
METHOD_ORIGIN = '<L=0'
HEAP_QUALIFIER_SET_REF = HEAPREF
METHOD_QUALIFIERS = HEAP_QUALIFIER_SET_REF
HEAP_METHOD_SIGNATURE_BLOCK_REF = HEAPREF
METHOD_SIGNATURE = HEAP_METHOD_SIGNATURE_BLOCK_REF


class METHOD_DESCRIPTION(Structure):
	"""2.2.41 MethodDescription"""
	structure = (
		('MethodName', METHOD_NAME),
		('MethodFlags', METHOD_FLAGS),
		('MethodPadding', METHOD_PADDING),
		('MethodOrigin', METHOD_ORIGIN),
		('MethodQualifiers', METHOD_QUALIFIERS),
		('InputSignature', METHOD_SIGNATURE),
		('OutputSignature', METHOD_SIGNATURE),
	)


class METHOD_SIGNATURE_BLOCK(Structure):
	"""2.2.48 MethodSignatureBlock"""
	structure = (
		('EncodingLength', ENCODING_LENGTH),
		('_ObjectBlock', '_-ObjectBlock', 'self["EncodingLength"]'),
		('ObjectBlock', ':'),
	)
	
	def __init__(self, data=None, alignment=0):
		Structure.__init__(self, data, alignment)
		if data is not None:
			self.fromString(data)
			if self['EncodingLength'] > 0:
				self['ObjectBlock'] = OBJECT_BLOCK(self['ObjectBlock'])


METHOD_HEAP = HEAP


class METHODS_PART(Structure):
	"""2.2.38 MethodsPart"""
	MethodDescriptionSize = 24  # 4+1+3+4+4+4+4 = 24 bytes
	
	structure = (
		('EncodingLength', ENCODING_LENGTH),
		('MethodCount', METHOD_COUNT),
		('MethodCountPadding', METHOD_COUNT_PADDING),
		('_MethodDescription', '_-MethodDescription',
		 'self["MethodCount"]*self.MethodDescriptionSize'),
		('MethodDescription', ':'),
		('MethodHeap', ':', METHOD_HEAP),
	)
	
	def getMethods(self):
		methods = OrderedDict()
		data = self['MethodDescription']
		heap = self['MethodHeap']['HeapItem']
		
		for _ in range(self['MethodCount']):
			methodDict = OrderedDict()
			itemn = METHOD_DESCRIPTION(data)
			
			if itemn['MethodFlags'] & WBEM_FLAVOR_ORIGIN_PROPAGATED:
				pass  # TODO: Handle propagated methods
			
			methodDict['name'] = ENCODED_STRING(heap[itemn['MethodName']:])['Character']
			methodDict['origin'] = itemn['MethodOrigin']
			
			if itemn['MethodQualifiers'] != 0xffffffff:
				qualifiersSet = QUALIFIER_SET(heap[itemn['MethodQualifiers']:])
				qualifiers = qualifiersSet.getQualifiers(heap)
				methodDict['qualifiers'] = qualifiers
			
			if itemn['InputSignature'] != 0xffffffff:
				inputSignature = METHOD_SIGNATURE_BLOCK(heap[itemn['InputSignature']:])
				if inputSignature['EncodingLength'] > 0:
					methodDict['InParams'] = \
						inputSignature['ObjectBlock']['ClassType']['CurrentClass'].getProperties()
					methodDict['InParamsRaw'] = inputSignature['ObjectBlock']
				else:
					methodDict['InParams'] = None
			
			if itemn['OutputSignature'] != 0xffffffff:
				outputSignature = METHOD_SIGNATURE_BLOCK(heap[itemn['OutputSignature']:])
				if outputSignature['EncodingLength'] > 0:
					methodDict['OutParams'] = \
						outputSignature['ObjectBlock']['ClassType']['CurrentClass'].getProperties()
					methodDict['OutParamsRaw'] = outputSignature['ObjectBlock']
				else:
					methodDict['OutParams'] = None
			
			data = data[len(itemn):]
			methods[methodDict['name']] = methodDict
		
		return methods


class CLASS_AND_METHODS_PART(Structure):
	"""2.2.14 ClassAndMethodsPart"""
	structure = (
		('ClassPart', ':', CLASS_PART),
		('MethodsPart', ':', METHODS_PART),
	)
	
	def __init__(self, data=None, alignment=0):
		Structure.__init__(self, None, alignment)
		if data is not None:
			# First, read just the ClassHeader to get EncodingLength
			classHeader = CLASS_HEADER(data)
			classPartLen = classHeader['EncodingLength']
			
			# Parse ClassPart with only its bytes
			self['ClassPart'] = CLASS_PART(data[:classPartLen])
			
			# Parse MethodsPart from remaining data
			self['MethodsPart'] = METHODS_PART(data[classPartLen:])
	
	def getClassName(self):
		pClassName = self['ClassPart']['ClassHeader']['ClassNameRef']
		cHeap = self['ClassPart']['ClassHeap']['HeapItem']
		
		if pClassName == 0xffffffff:
			return 'None'
		else:
			className = ENCODED_STRING(cHeap[pClassName:])['Character']
			derivationList = self['ClassPart']['DerivationList']['ClassNameEncoding']
			
			while len(derivationList) > 0:
				superClass = ENCODED_STRING(derivationList)['Character']
				className += ' : %s ' % superClass
				derivationList = derivationList[len(ENCODED_STRING(derivationList)) + 4:]
			
			return className
	
	def getQualifiers(self):
		return self["ClassPart"].getQualifiers()
	
	def getProperties(self):
		return self["ClassPart"].getProperties()
	
	def getMethods(self):
		return self["MethodsPart"].getMethods()


# 2.2.13 CurrentClass
CURRENT_CLASS = CLASS_AND_METHODS_PART

# 2.2.12 ParentClass
PARENT_CLASS = CLASS_AND_METHODS_PART

# Instance structures
INSTANCE_FLAGS = 'B=0'
INSTANCE_CLASS_NAME = HEAP_STRING_REF
NULL_AND_DEFAULT_FLAG = 'B=0'
NDTABLE = NULL_AND_DEFAULT_FLAG


class CURRENT_CLASS_NO_METHODS(CLASS_AND_METHODS_PART):
	"""Class without methods part"""
	structure = (
		('ClassPart', ':', CLASS_PART),
	)
	
	def getMethods(self):
		return OrderedDict()


class INSTANCE_PROP_QUALIFIER_SET(Structure):
	"""2.2.57.1 InstancePropQualifierSet"""
	commonHdr = (
		('InstPropQualSetFlag', 'B=0'),
	)
	
	noQualifiers = (
		('QualifierSet', ':', QUALIFIER_SET),
	)
	
	def __init__(self, data=None, alignment=0):
		Structure.__init__(self, data, alignment)
		self.structure = ()
		if data is not None:
			self.fromString(data)
			if self['InstPropQualSetFlag'] == 2:
				raise Exception("InstPropQualSetFlag == 2 not supported")
			self.fromString(data)
		else:
			self.data = None


class INSTANCE_QUALIFIER_SET(Structure):
	"""2.2.57 InstanceQualifierSet"""
	structure = (
		('QualifierSet', ':', QUALIFIER_SET),
		('InstancePropQualifierSet', ':', INSTANCE_PROP_QUALIFIER_SET),
	)


INSTANCE_HEAP = HEAP


class INSTANCE_TYPE(Structure):
	"""2.2.53 InstanceType"""
	commonHdr = (
		('CurrentClass', ':', CURRENT_CLASS_NO_METHODS),
		('EncodingLength', '<L=0'),
		('InstanceFlags', INSTANCE_FLAGS),
		('InstanceClassName', INSTANCE_CLASS_NAME),
		('_NdTable_ValueTable', '_-NdTable_ValueTable',
		 'self["CurrentClass"]["ClassPart"]["ClassHeader"]["NdTableValueTableLength"]'),
		('NdTable_ValueTable', ':'),
		('InstanceQualifierSet', ':', INSTANCE_QUALIFIER_SET),
		('InstanceHeap', ':', INSTANCE_HEAP),
	)
	
	def __init__(self, data=None, alignment=0):
		Structure.__init__(self, data, alignment)
		self.structure = ()
		if data is not None:
			self.fromString(data)
			self.NdTableSize = \
				(self['CurrentClass']['ClassPart']['PropertyLookupTable']['PropertyCount'] - 1) // 4 + 1
			self.fromString(data)
		else:
			self.data = None
	
	def __processNdTable(self, properties):
		"""Process Null/Default table"""
		octetCount = (len(properties) - 1) // 4 + 1
		packedNdTable = self['NdTable_ValueTable'][:octetCount]
		unpackedNdTable = []
		for byte in packedNdTable:
			if isinstance(byte, int):
				b = byte
			else:
				b = ord(byte)
			for shift in (0, 2, 4, 6):
				unpackedNdTable.append((b >> shift) & 0b11)
		
		for key in properties:
			ndEntry = unpackedNdTable[properties[key]['order']]
			properties[key]['null_default'] = bool(ndEntry & 0b01)
			properties[key]['inherited_default'] = bool(ndEntry & 0b10)
		
		return octetCount
	
	@staticmethod
	def __isNonNullNumber(prop):
		return prop['type'] & ~Inherited in CIM_NUMBER_TYPES and not prop['null_default']
	
	def getValues(self, properties):
		"""Get instance values"""
		heap = self["InstanceHeap"]["HeapItem"]
		valueTableOff = self.__processNdTable(properties)
		valueTable = self['NdTable_ValueTable'][valueTableOff:]
		sorted_props = sorted(list(properties.keys()), key=lambda k: properties[k]['order'])
		
		for key in sorted_props:
			pType = properties[key]['type'] & (~(CIM_ARRAY_FLAG | Inherited))
			if properties[key]['type'] & CIM_ARRAY_FLAG:
				unpackStr = HEAPREF[:-2]
			else:
				unpackStr = CIM_TYPES_REF[pType][:-2]
			dataSize = calcsize(unpackStr)
			
			try:
				itemValue = unpack(unpackStr, valueTable[:dataSize])[0]
			except:
				LOG.error("getValues: Error Unpacking!")
				itemValue = 0xffffffff
			
			if itemValue != 0 or self.__isNonNullNumber(properties[key]):
				value = ENCODED_VALUE.getValue(properties[key]['type'], itemValue, heap)
				properties[key]['value'] = value
			elif properties[key]['inherited'] == 0:
				properties[key]['value'] = None
			
			valueTable = valueTable[dataSize:]
		
		return properties


class CLASS_TYPE(Structure):
	"""Class type structure"""
	structure = (
		('ParentClass', ':', PARENT_CLASS),
		('CurrentClass', ':', CURRENT_CLASS),
	)


class DECORATION(Structure):
	"""2.2.7 Decoration - Server name and namespace"""
	structure = (
		('DecServerName', ':', ENCODED_STRING),
		('DecNamespaceName', ':', ENCODED_STRING),
	)


class OBJECT_BLOCK(Structure):
	"""2.2.5 ObjectBlock"""
	commonHdr = (
		('ObjectFlags', OBJECT_FLAGS),
	)
	
	decoration = (
		('Decoration', ':', DECORATION),
	)
	
	instanceType = (
		('InstanceType', ':', INSTANCE_TYPE),
	)
	
	classType = (
		('ClassType', ':', CLASS_TYPE),
	)
	
	def __init__(self, data=None, alignment=0):
		Structure.__init__(self, data, alignment)
		self.structure = ()
		self.ctParent = None
		self.ctCurrent = None
		
		if data is not None:
			self.fromString(data)
			if ord(data[0:1]) & 0x04:
				self.structure += self.decoration
			if ord(data[0:1]) & 0x01:
				self.structure += self.classType
			else:
				self.structure += self.instanceType
			self.fromString(data)
		else:
			self.data = None
	
	def isInstance(self):
		if self['ObjectFlags'] & 0x01:
			return False
		return True
	
	def parseClass(self, pClass, cInstance=None):
		"""Parse a class into a dictionary"""
		classDict = OrderedDict()
		classDict['name'] = pClass.getClassName()
		classDict['qualifiers'] = pClass.getQualifiers()
		classDict['properties'] = pClass.getProperties()
		classDict['methods'] = pClass.getMethods()
		
		if cInstance is not None:
			classDict['values'] = cInstance.getValues(classDict['properties'])
		else:
			classDict['values'] = None
		
		return classDict
	
	def parseObject(self):
		"""Parse the object block"""
		if (self['ObjectFlags'] & 0x01) == 0:
			# Instance
			ctCurrent = self['InstanceType']['CurrentClass']
			currentName = ctCurrent.getClassName()
			if currentName is not None:
				self.ctCurrent = self.parseClass(ctCurrent, self['InstanceType'])
			return
		else:
			# Class
			ctParent = self['ClassType']['ParentClass']
			ctCurrent = self['ClassType']['CurrentClass']
			
			parentName = ctParent.getClassName()
			if parentName is not None:
				self.ctParent = self.parseClass(ctParent)
			
			currentName = ctCurrent.getClassName()
			if currentName is not None:
				self.ctCurrent = self.parseClass(ctCurrent)
	
	def printInformation(self):
		"""Print object information"""
		if (self['ObjectFlags'] & 0x01) == 0:
			# Instance
			ctCurrent = self['InstanceType']['CurrentClass']
			currentName = ctCurrent.getClassName()
			if currentName is not None:
				self._printClass(ctCurrent, self['InstanceType'])
			return
		else:
			# Class
			ctParent = self['ClassType']['ParentClass']
			ctCurrent = self['ClassType']['CurrentClass']
			
			parentName = ctParent.getClassName()
			if parentName is not None:
				self._printClass(ctParent)
			
			currentName = ctCurrent.getClassName()
			if currentName is not None:
				self._printClass(ctCurrent)
	
	def _printClass(self, pClass, cInstance=None):
		"""Print class details"""
		qualifiers = pClass.getQualifiers()
		for qualifier in qualifiers:
			print("[%s]" % qualifier)
		
		className = pClass.getClassName()
		print("class %s \n{" % className)
		
		properties = pClass.getProperties()
		if cInstance is not None:
			properties = cInstance.getValues(properties)
		
		for pName in properties:
			qualifiers = properties[pName]['qualifiers']
			for qName in qualifiers:
				if qName != 'CIMTYPE':
					print('\t[%s(%s)]' % (qName, qualifiers[qName]))
			
			print('\t%s %s' % (properties[pName]['stype'], properties[pName]['name']), end=' ')
			
			if properties[pName]['value'] is not None:
				cimType = properties[pName]['type'] & (~Inherited)
				if cimType == CIM_TYPE_ENUM.CIM_TYPE_OBJECT:
					print('= IWbemClassObject\n')
				elif cimType == CIM_TYPE_ENUM.CIM_ARRAY_OBJECT:
					if properties[pName]['value'] == 0:
						print('= %s\n' % properties[pName]['value'])
					else:
						print('= %s\n' % list('IWbemClassObject' for _ in 
							  range(len(properties[pName]['value']))))
				else:
					print('= %s\n' % properties[pName]['value'])
			else:
				print('\n')
		
		print()
		
		methods = pClass.getMethods()
		for methodName in methods:
			if 'qualifiers' in methods[methodName]:
				for qualifier in methods[methodName]['qualifiers']:
					print('\t[%s]' % qualifier)
			
			if methods[methodName].get('InParams') is None and \
			   methods[methodName].get('OutParams') is None:
				print('\t%s %s();\n' % ('void', methodName))
			elif methods[methodName].get('InParams') is None and \
				 methods[methodName].get('OutParams') is not None and \
				 len(methods[methodName]['OutParams']) == 1:
				print('\t%s %s();\n' % (
					methods[methodName]['OutParams']['ReturnValue']['stype'], methodName))
			else:
				returnValue = ''
				if methods[methodName].get('OutParams') is not None:
					if 'ReturnValue' in methods[methodName]['OutParams']:
						returnValue = methods[methodName]['OutParams']['ReturnValue']['stype']
				
				print('\t%s %s(\n' % (returnValue, methodName), end=' ')
				
				if methods[methodName].get('InParams') is not None:
					for pName in methods[methodName]['InParams']:
						print('\t\t[in]    %s %s,' % (
							methods[methodName]['InParams'][pName]['stype'], pName))
				
				if methods[methodName].get('OutParams') is not None:
					for pName in methods[methodName]['OutParams']:
						if pName != 'ReturnValue':
							print('\t\t[out]    %s %s,' % (
								methods[methodName]['OutParams'][pName]['stype'], pName))
				
				print('\t);\n')
		
		print("}")


class ENCODING_UNIT(Structure):
	"""2.2.1 EncodingUnit"""
	structure = (
		('Signature', SIGNATURE),
		('ObjectEncodingLength', OBJECT_ENCODING_LENGTH),
		('_ObjectBlock', '_-ObjectBlock', 'self["ObjectEncodingLength"]'),
		('ObjectBlock', ':'),
	)
	
	def __init__(self, data=None, alignment=0):
		Structure.__init__(self, data, alignment)
		if data is not None:
			self.fromString(data)
			self['ObjectBlock'] = OBJECT_BLOCK(self['ObjectBlock'])


################################################################################
# NDR Structures for RPC
################################################################################

class UCHAR_ARRAY_CV(NDRSTRUCT):
	structure = (
		('MaxCount', '<L=len(Data)'),
		('Offset', '<L=0'),
		('ActualCount', '<L=len(Data)'),
		('Data', ':'),
	)


class PUCHAR_ARRAY_CV(NDRPOINTER):
	referent = (
		('Data', UCHAR_ARRAY_CV),
	)


class PMInterfacePointer_ARRAY_CV(NDRUniConformantVaryingArray):
	item = PMInterfacePointer


################################################################################
# RPC CALLS
################################################################################

# 3.1.4.1 IWbemLevel1Login Interface

class IWbemLevel1Login_EstablishPosition(DCOMCALL):
	opnum = 3
	structure = (
		('reserved1', LPWSTR),
		('reserved2', DWORD),
	)


class IWbemLevel1Login_EstablishPositionResponse(DCOMANSWER):
	structure = (
		('LocaleVersion', DWORD),
		('ErrorCode', error_status_t),
	)


class IWbemLevel1Login_RequestChallenge(DCOMCALL):
	opnum = 4
	structure = (
		('reserved1', LPWSTR),
		('reserved2', LPWSTR),
	)


class IWbemLevel1Login_RequestChallengeResponse(DCOMANSWER):
	structure = (
		('reserved3', UCHAR_ARRAY_CV),
		('ErrorCode', error_status_t),
	)


class IWbemLevel1Login_WBEMLogin(DCOMCALL):
	opnum = 5
	structure = (
		('reserved1', LPWSTR),
		('reserved2', PUCHAR_ARRAY_CV),
		('reserved3', LONG),
		('reserved4', PMInterfacePointer),
	)


class IWbemLevel1Login_WBEMLoginResponse(DCOMANSWER):
	structure = (
		('reserved5', UCHAR_ARRAY_CV),
		('ErrorCode', error_status_t),
	)


class IWbemLevel1Login_NTLMLogin(DCOMCALL):
	opnum = 6
	structure = (
		('wszNetworkResource', LPWSTR),
		('wszPreferredLocale', LPWSTR),
		('lFlags', LONG),
		('pCtx', PMInterfacePointer),
	)


class IWbemLevel1Login_NTLMLoginResponse(DCOMANSWER):
	structure = (
		('ppNamespace', PMInterfacePointer),
		('ErrorCode', error_status_t),
	)


# 3.1.4.3 IWbemServices Interface

class IWbemServices_OpenNamespace(DCOMCALL):
	opnum = 3
	structure = (
		('strNamespace', BSTR),
		('lFlags', LONG),
		('pCtx', PMInterfacePointer),
		('ppWorkingNamespace', PMInterfacePointer),
		('ppResult', PMInterfacePointer),
	)


class IWbemServices_OpenNamespaceResponse(DCOMANSWER):
	structure = (
		('ppWorkingNamespace', PMInterfacePointer),
		('ppResult', PMInterfacePointer),
		('ErrorCode', error_status_t),
	)


class IWbemServices_CancelAsyncCall(DCOMCALL):
	opnum = 4
	structure = (
		('IWbemObjectSink', PMInterfacePointer),
	)


class IWbemServices_CancelAsyncCallResponse(DCOMANSWER):
	structure = (
		('ErrorCode', error_status_t),
	)


class IWbemServices_QueryObjectSink(DCOMCALL):
	opnum = 5
	structure = (
		('lFlags', LONG),
	)


class IWbemServices_QueryObjectSinkResponse(DCOMANSWER):
	structure = (
		('ppResponseHandler', PMInterfacePointer),
		('ErrorCode', error_status_t),
	)


class IWbemServices_GetObject(DCOMCALL):
	opnum = 6
	structure = (
		('strObjectPath', BSTR),
		('lFlags', LONG),
		('pCtx', PMInterfacePointer),
		('ppObject', PMInterfacePointer),
		('ppCallResult', PMInterfacePointer),
	)


class IWbemServices_GetObjectResponse(DCOMANSWER):
	structure = (
		('ppObject', PPMInterfacePointer),
		('ppCallResult', PPMInterfacePointer),
		('ErrorCode', error_status_t),
	)


class IWbemServices_GetObjectAsync(DCOMCALL):
	opnum = 7
	structure = (
		('strObjectPath', BSTR),
		('lFlags', LONG),
		('pCtx', PMInterfacePointer),
		('pResponseHandler', PMInterfacePointer),
	)


class IWbemServices_GetObjectAsyncResponse(DCOMANSWER):
	structure = (
		('ErrorCode', error_status_t),
	)


class IWbemServices_PutClass(DCOMCALL):
	opnum = 8
	structure = (
		('pObject', PMInterfacePointer),
		('lFlags', LONG),
		('pCtx', PMInterfacePointer),
		('ppCallResult', PPMInterfacePointer),
	)


class IWbemServices_PutClassResponse(DCOMANSWER):
	structure = (
		('ppCallResult', PPMInterfacePointer),
		('ErrorCode', error_status_t),
	)


class IWbemServices_PutClassAsync(DCOMCALL):
	opnum = 9
	structure = (
		('pObject', PMInterfacePointer),
		('lFlags', LONG),
		('pCtx', PMInterfacePointer),
		('pResponseHandler', PMInterfacePointer),
	)


class IWbemServices_PutClassAsyncResponse(DCOMANSWER):
	structure = (
		('ErrorCode', error_status_t),
	)


class IWbemServices_DeleteClass(DCOMCALL):
	opnum = 10
	structure = (
		('strClass', BSTR),
		('lFlags', LONG),
		('pCtx', PMInterfacePointer),
		('ppCallResult', PPMInterfacePointer),
	)


class IWbemServices_DeleteClassResponse(DCOMANSWER):
	structure = (
		('ppCallResult', PPMInterfacePointer),
		('ErrorCode', error_status_t),
	)


class IWbemServices_DeleteClassAsync(DCOMCALL):
	opnum = 11
	structure = (
		('strClass', BSTR),
		('lFlags', LONG),
		('pCtx', PMInterfacePointer),
		('pResponseHandler', PMInterfacePointer),
	)


class IWbemServices_DeleteClassAsyncResponse(DCOMANSWER):
	structure = (
		('ErrorCode', error_status_t),
	)


class IWbemServices_CreateClassEnum(DCOMCALL):
	opnum = 12
	structure = (
		('strSuperClass', BSTR),
		('lFlags', LONG),
		('pCtx', PMInterfacePointer),
	)


class IWbemServices_CreateClassEnumResponse(DCOMANSWER):
	structure = (
		('ppEnum', PMInterfacePointer),
		('ErrorCode', error_status_t),
	)


class IWbemServices_CreateClassEnumAsync(DCOMCALL):
	opnum = 13
	structure = (
		('strSuperClass', BSTR),
		('lFlags', LONG),
		('pCtx', PMInterfacePointer),
		('pResponseHandler', PMInterfacePointer),
	)


class IWbemServices_CreateClassEnumAsyncResponse(DCOMANSWER):
	structure = (
		('ErrorCode', error_status_t),
	)


class IWbemServices_PutInstance(DCOMCALL):
	opnum = 14
	structure = (
		('pInst', PMInterfacePointer),
		('lFlags', LONG),
		('pCtx', PMInterfacePointer),
		('ppCallResult', PPMInterfacePointer),
	)


class IWbemServices_PutInstanceResponse(DCOMANSWER):
	structure = (
		('ppCallResult', PPMInterfacePointer),
		('ErrorCode', error_status_t),
	)


class IWbemServices_PutInstanceAsync(DCOMCALL):
	opnum = 15
	structure = (
		('pInst', PMInterfacePointer),
		('lFlags', LONG),
		('pCtx', PMInterfacePointer),
		('pResponseHandler', PMInterfacePointer),
	)


class IWbemServices_PutInstanceAsyncResponse(DCOMANSWER):
	structure = (
		('ErrorCode', error_status_t),
	)


class IWbemServices_DeleteInstance(DCOMCALL):
	opnum = 16
	structure = (
		('strObjectPath', BSTR),
		('lFlags', LONG),
		('pCtx', PMInterfacePointer),
		('ppCallResult', PPMInterfacePointer),
	)


class IWbemServices_DeleteInstanceResponse(DCOMANSWER):
	structure = (
		('ppCallResult', PPMInterfacePointer),
		('ErrorCode', error_status_t),
	)


class IWbemServices_DeleteInstanceAsync(DCOMCALL):
	opnum = 17
	structure = (
		('strObjectPath', BSTR),
		('lFlags', LONG),
		('pCtx', PMInterfacePointer),
		('pResponseHandler', PMInterfacePointer),
	)


class IWbemServices_DeleteInstanceAsyncResponse(DCOMANSWER):
	structure = (
		('ErrorCode', error_status_t),
	)


class IWbemServices_CreateInstanceEnum(DCOMCALL):
	opnum = 18
	structure = (
		('strSuperClass', BSTR),
		('lFlags', LONG),
		('pCtx', PMInterfacePointer),
	)


class IWbemServices_CreateInstanceEnumResponse(DCOMANSWER):
	structure = (
		('ppEnum', PMInterfacePointer),
		('ErrorCode', error_status_t),
	)


class IWbemServices_CreateInstanceEnumAsync(DCOMCALL):
	opnum = 19
	structure = (
		('strSuperClass', BSTR),
		('lFlags', LONG),
		('pCtx', PMInterfacePointer),
		('pResponseHandler', PMInterfacePointer),
	)


class IWbemServices_CreateInstanceEnumAsyncResponse(DCOMANSWER):
	structure = (
		('ErrorCode', error_status_t),
	)


class IWbemServices_ExecQuery(DCOMCALL):
	opnum = 20
	structure = (
		('strQueryLanguage', BSTR),
		('strQuery', BSTR),
		('lFlags', LONG),
		('pCtx', PMInterfacePointer),
	)


class IWbemServices_ExecQueryResponse(DCOMANSWER):
	structure = (
		('ppEnum', PMInterfacePointer),
		('ErrorCode', error_status_t),
	)


class IWbemServices_ExecQueryAsync(DCOMCALL):
	opnum = 21
	structure = (
		('strQueryLanguage', BSTR),
		('strQuery', BSTR),
		('lFlags', LONG),
		('pCtx', PMInterfacePointer),
		('pResponseHandler', PMInterfacePointer),
	)


class IWbemServices_ExecQueryAsyncResponse(DCOMANSWER):
	structure = (
		('ErrorCode', error_status_t),
	)


class IWbemServices_ExecNotificationQuery(DCOMCALL):
	opnum = 22
	structure = (
		('strQueryLanguage', BSTR),
		('strQuery', BSTR),
		('lFlags', LONG),
		('pCtx', PMInterfacePointer),
	)


class IWbemServices_ExecNotificationQueryResponse(DCOMANSWER):
	structure = (
		('ppEnum', PMInterfacePointer),
		('ErrorCode', error_status_t),
	)


class IWbemServices_ExecNotificationQueryAsync(DCOMCALL):
	opnum = 23
	structure = (
		('strQueryLanguage', BSTR),
		('strQuery', BSTR),
		('lFlags', LONG),
		('pCtx', PMInterfacePointer),
		('pResponseHandler', PMInterfacePointer),
	)


class IWbemServices_ExecNotificationQueryAsyncResponse(DCOMANSWER):
	structure = (
		('ErrorCode', error_status_t),
	)


class IWbemServices_ExecMethod(DCOMCALL):
	opnum = 24
	structure = (
		('strObjectPath', BSTR),
		('strMethodName', BSTR),
		('lFlags', LONG),
		('pCtx', PMInterfacePointer),
		('pInParams', PMInterfacePointer),
		('ppOutParams', PPMInterfacePointer),
		('ppCallResult', PPMInterfacePointer),
	)


class IWbemServices_ExecMethodResponse(DCOMANSWER):
	structure = (
		('ppOutParams', PPMInterfacePointer),
		('ppCallResult', PPMInterfacePointer),
		('ErrorCode', error_status_t),
	)


class IWbemServices_ExecMethodAsync(DCOMCALL):
	opnum = 25
	structure = (
		('strObjectPath', BSTR),
		('strMethodName', BSTR),
		('lFlags', LONG),
		('pCtx', PMInterfacePointer),
		('pInParams', PMInterfacePointer),
		('pResponseHandler', PMInterfacePointer),
	)


class IWbemServices_ExecMethodAsyncResponse(DCOMANSWER):
	structure = (
		('ErrorCode', error_status_t),
	)


# 3.1.4.4 IEnumWbemClassObject Interface

class IEnumWbemClassObject_Reset(DCOMCALL):
	opnum = 3
	structure = ()


class IEnumWbemClassObject_ResetResponse(DCOMANSWER):
	structure = (
		('ErrorCode', error_status_t),
	)


class IEnumWbemClassObject_Next(DCOMCALL):
	opnum = 4
	structure = (
		('lTimeout', LONG),
		('uCount', ULONG),
	)


class IEnumWbemClassObject_NextResponse(DCOMANSWER):
	structure = (
		('apObjects', PMInterfacePointer_ARRAY_CV),
		('puReturned', ULONG),
		('ErrorCode', error_status_t),
	)


class IEnumWbemClassObject_NextAsync(DCOMCALL):
	opnum = 5
	structure = (
		('lTimeout', LONG),
		('pSink', PMInterfacePointer),
	)


class IEnumWbemClassObject_NextAsyncResponse(DCOMANSWER):
	structure = (
		('ErrorCode', error_status_t),
	)


class IEnumWbemClassObject_Clone(DCOMCALL):
	opnum = 6
	structure = ()


class IEnumWbemClassObject_CloneResponse(DCOMANSWER):
	structure = (
		('ppEnum', PMInterfacePointer),
		('ErrorCode', error_status_t),
	)


class IEnumWbemClassObject_Skip(DCOMCALL):
	opnum = 7
	structure = (
		('lTimeout', LONG),
		('uCount', ULONG),
	)


class IEnumWbemClassObject_SkipResponse(DCOMANSWER):
	structure = (
		('ErrorCode', error_status_t),
	)


# IWbemCallResult Interface

class IWbemCallResult_QueryInterface(DCOMCALL):
	opnum = 0
	structure = ()


class IWbemCallResult_GetResultObject(DCOMCALL):
	opnum = 3
	structure = (
		('lTimeout', LONG),
	)


class IWbemCallResult_GetResultObjectResponse(DCOMANSWER):
	structure = (
		('ppResultObject', PMInterfacePointer),
		('ErrorCode', error_status_t),
	)


class IWbemCallResult_GetResultString(DCOMCALL):
	opnum = 4
	structure = (
		('lTimeout', LONG),
	)


class IWbemCallResult_GetResultStringResponse(DCOMANSWER):
	structure = (
		('pstrResultString', BSTR),
		('ErrorCode', error_status_t),
	)


class IWbemCallResult_GetResultServices(DCOMCALL):
	opnum = 5
	structure = (
		('lTimeout', LONG),
	)


class IWbemCallResult_GetResultServicesResponse(DCOMANSWER):
	structure = (
		('ppServices', PMInterfacePointer),
		('ErrorCode', error_status_t),
	)


class IWbemCallResult_GetCallStatus(DCOMCALL):
	opnum = 6
	structure = (
		('lTimeout', LONG),
	)


class IWbemCallResult_GetCallStatusResponse(DCOMANSWER):
	structure = (
		('plStatus', LONG),
		('ErrorCode', error_status_t),
	)


# IWbemLoginClientID Interface

class IWbemLoginClientID_SetClientInfo(DCOMCALL):
	opnum = 3
	structure = (
		('wszClientMachine', LPWSTR),
		('lClientProcId', LONG),
		('lReserved', LONG),
	)


class IWbemLoginClientID_SetClientInfoResponse(DCOMANSWER):
	structure = (
		('ErrorCode', error_status_t),
	)


################################################################################
# INTERFACE CLASSES
################################################################################

class IWbemClassObject(IRemUnknown):
	"""
	WMI Class/Instance Object.
	
	Represents a WMI class definition or instance.
	Provides access to properties and methods.
	"""
	
	def __init__(self, interface, iWbemServices=None):
		IRemUnknown.__init__(self, interface)
		self._iid = IID_IWbemClassObject
		self.__iWbemServices = iWbemServices
		self.__methods = None
		
		# Parse the OBJREF_CUSTOM data
		objRefType = OBJREF_CUSTOM(interface.get_objRef())
		self.encodingUnit = ENCODING_UNIT(objRefType['pObjectData'])
		self.encodingUnit['ObjectBlock'].parseObject()
		
		# Create properties as attributes
		self.createProperties(self.getProperties())
		
		# For class objects, pre-setup methods
		if self.encodingUnit['ObjectBlock'].isInstance() is False:
			methods = self.getMethods()
			if methods:
				self.createMethods(self.getClassName(), methods)
	
	def __getattr__(self, attr):
		"""Dynamic method invocation support for instances"""
		if attr.startswith('_'):
			raise AttributeError("%r object has no attribute %r" % (self.__class__, attr))
		
		# Only for instances - class methods are set up in __init__
		if self.encodingUnit['ObjectBlock'].isInstance() is False:
			raise AttributeError("%r object has no attribute %r" % (self.__class__, attr))
		
		# Check if methods have been loaded from class definition
		if self.__methods is not None and attr in self.__methods:
			properties = self.getProperties()
			keyProperty = None
			for pName in properties:
				if 'key' in properties[pName].get('qualifiers', {}):
					keyProperty = pName
					break
			
			if keyProperty is None:
				raise AttributeError("%r object has no attribute %r" % (self.__class__, attr))
			
			# Build instance path for ExecMethod
			if self.getProperties()[keyProperty]['stype'] != 'string':
				instanceName = '%s.%s=%s' % (
					self.getClassName(), 
					keyProperty, 
					self.getProperties()[keyProperty]['value']
				)
			else:
				instanceName = '%s.%s="%s"' % (
					self.getClassName(), 
					keyProperty, 
					self.getProperties()[keyProperty]['value']
				)
			self.createMethods(instanceName, self.__methods)
			return getattr(self, attr)
		
		raise AttributeError("%r object has no attribute %r" % (self.__class__, attr))
	
	async def loadInstanceMethods(self):
		"""
		Load methods for an instance by fetching the class definition.
		
		For instances, methods are not included in the WMIO encoding.
		We need to fetch the class definition to get method signatures.
		"""
		if self.__iWbemServices is None:
			raise Exception("Cannot load instance methods: no IWbemServices reference")
		
		if self.encodingUnit['ObjectBlock'].isInstance() is False:
			# Already a class, methods are already available
			return self.getMethods()
		
		if self.__methods is not None:
			# Already loaded
			return self.__methods
		
		# Get the class definition
		className = self.getClassName()
		result, err = await self.__iWbemServices.GetObject(className)
		if err is not None:
			raise Exception(f"Failed to get class definition for {className}: {err}")
		
		classObj, _ = result
		self.__methods = classObj.getMethods()
		return self.__methods
	
	def parseObject(self):
		"""Parse the encoding unit"""
		self.encodingUnit['ObjectBlock'].parseObject()
	
	def getObject(self):
		"""Get the object block"""
		return self.encodingUnit['ObjectBlock']
	
	def getClassName(self):
		"""Get the class name"""
		if self.encodingUnit['ObjectBlock'].isInstance() is False:
			return self.encodingUnit['ObjectBlock']['ClassType']['CurrentClass'].getClassName().split(' ')[0]
		else:
			return self.encodingUnit['ObjectBlock']['InstanceType']['CurrentClass'].getClassName().split(' ')[0]
	
	def printInformation(self):
		"""Print object information"""
		return self.encodingUnit['ObjectBlock'].printInformation()
	
	def getProperties(self):
		"""Get all properties"""
		if self.encodingUnit['ObjectBlock'].ctCurrent is None:
			return {}
		return self.encodingUnit['ObjectBlock'].ctCurrent['properties']
	
	def getMethods(self):
		"""Get all methods"""
		if self.encodingUnit['ObjectBlock'].ctCurrent is None:
			return {}
		return self.encodingUnit['ObjectBlock'].ctCurrent['methods']
	
	@staticmethod
	def __ndEntry(index, null_default, inherited_default):
		"""Build NdTable entry"""
		return (bool(null_default) << 1 | bool(inherited_default)) << (2 * (index % 4))
	
	def marshalMe(self):
		"""Marshal the object for RPC calls"""
		instanceHeap = b''
		valueTable = b''
		ndTable = 0
		
		parametersClass = ENCODED_STRING()
		parametersClass['Character'] = self.getClassName()
		instanceHeap += parametersClass.getData()
		curHeapPtr = len(instanceHeap)
		
		properties = self.getProperties()
		
		for i, propName in enumerate(properties):
			propRecord = properties[propName]
			itemValue = getattr(self, propName, None)
			propIsInherited = propRecord['inherited']
			
			pType = propRecord['type'] & (~(CIM_ARRAY_FLAG | Inherited))
			
			if propRecord['type'] & CIM_ARRAY_FLAG:
				packStr = HEAPREF[:-2]
			else:
				packStr = CIM_TYPES_REF[pType][:-2]
			
			if pType in (CIM_TYPE_ENUM.CIM_TYPE_SINT8, CIM_TYPE_ENUM.CIM_TYPE_UINT8,
						CIM_TYPE_ENUM.CIM_TYPE_SINT16, CIM_TYPE_ENUM.CIM_TYPE_UINT16,
						CIM_TYPE_ENUM.CIM_TYPE_SINT32, CIM_TYPE_ENUM.CIM_TYPE_UINT32,
						CIM_TYPE_ENUM.CIM_TYPE_SINT64, CIM_TYPE_ENUM.CIM_TYPE_UINT64):
				if itemValue is None:
					ndTable |= self.__ndEntry(i, True, propIsInherited)
					valueTable += pack(packStr, 0)
				else:
					valueTable += pack(packStr, int(itemValue))
			elif pType == CIM_TYPE_ENUM.CIM_TYPE_BOOLEAN:
				if itemValue is None:
					ndTable |= self.__ndEntry(i, True, propIsInherited)
					valueTable += pack(packStr, False)
				else:
					valueTable += pack(packStr, bool(itemValue))
			elif pType == CIM_TYPE_ENUM.CIM_TYPE_OBJECT:
				valueTable += b'\x00' * 4
				if itemValue is None:
					ndTable |= self.__ndEntry(i, True, True)
			elif pType not in (CIM_TYPE_ENUM.CIM_TYPE_STRING,
							  CIM_TYPE_ENUM.CIM_TYPE_DATETIME,
							  CIM_TYPE_ENUM.CIM_TYPE_REFERENCE):
				if itemValue is None:
					ndTable |= self.__ndEntry(i, True, propIsInherited)
					valueTable += pack(packStr, -1)
				else:
					valueTable += pack(packStr, itemValue)
			else:
				if itemValue == '' or itemValue is None:
					ndTable |= self.__ndEntry(i, True, True)
					valueTable += pack('<L', 0)
				else:
					strIn = ENCODED_STRING()
					strIn['Character'] = itemValue
					valueTable += pack('<L', curHeapPtr)
					instanceHeap += strIn.getData()
					curHeapPtr = len(instanceHeap)
		
		ndTableLen = (len(properties) - 1) // 4 + 1
		packedNdTable = b''
		for i in range(ndTableLen):
			packedNdTable += pack('B', ndTable & 0xff)
			ndTable >>= 8
		
		# Update the structure
		objRef = self.get_objRef()
		objRef = OBJREF_CUSTOM(objRef)
		encodingUnit = ENCODING_UNIT(objRef['pObjectData'])
		currentClass = encodingUnit['ObjectBlock']['InstanceType']['CurrentClass']
		encodingUnit['ObjectBlock']['InstanceType']['CurrentClass'] = b''
		encodingUnit['ObjectBlock']['InstanceType']['NdTable_ValueTable'] = packedNdTable + valueTable
		encodingUnit['ObjectBlock']['InstanceType']['InstanceHeap']['HeapLength'] = len(instanceHeap) | 0x80000000
		encodingUnit['ObjectBlock']['InstanceType']['InstanceHeap']['HeapItem'] = instanceHeap
		encodingUnit['ObjectBlock']['InstanceType']['EncodingLength'] = len(encodingUnit['ObjectBlock']['InstanceType'])
		encodingUnit['ObjectBlock']['InstanceType']['CurrentClass'] = currentClass
		encodingUnit['ObjectEncodingLength'] = len(encodingUnit['ObjectBlock'])
		
		objRef['pObjectData'] = encodingUnit
		return objRef
	
	def SpawnInstance(self):
		"""
		Create a new instance from this class definition.
		Similar to IWbemClassObject::SpawnInstance in COM.
		"""
		if self.encodingUnit['ObjectBlock'].isInstance() is False:
			encodingUnit = ENCODING_UNIT()
			instanceData = OBJECT_BLOCK()
			instanceData.structure += OBJECT_BLOCK.decoration
			instanceData.structure += OBJECT_BLOCK.instanceType
			instanceData['ObjectFlags'] = 6
			instanceData['Decoration'] = self.encodingUnit['ObjectBlock']['Decoration'].getData()
			
			instanceType = INSTANCE_TYPE()
			instanceType['CurrentClass'] = b''
			
			instanceHeap = b''
			valueTable = b''
			
			parametersClass = ENCODED_STRING()
			parametersClass['Character'] = self.getClassName()
			instanceHeap += parametersClass.getData()
			curHeapPtr = len(instanceHeap)
			ndTable = 0
			
			properties = self.getProperties()
			
			for i, propName in enumerate(properties):
				propRecord = properties[propName]
				pType = propRecord['type'] & (~(CIM_ARRAY_FLAG | Inherited))
				
				if propRecord['type'] & CIM_ARRAY_FLAG:
					packStr = HEAPREF[:-2]
				else:
					packStr = CIM_TYPES_REF[pType][:-2]
				
				if propRecord['type'] & CIM_ARRAY_FLAG:
					valueTable += pack(packStr, 0)
				elif pType not in (CIM_TYPE_ENUM.CIM_TYPE_STRING,
								  CIM_TYPE_ENUM.CIM_TYPE_DATETIME,
								  CIM_TYPE_ENUM.CIM_TYPE_REFERENCE,
								  CIM_TYPE_ENUM.CIM_TYPE_OBJECT):
					valueTable += pack(packStr, 0)
				elif pType == CIM_TYPE_ENUM.CIM_TYPE_OBJECT:
					valueTable += b'\x00' * 4
					ndTable |= self.__ndEntry(i, True, True)
				else:
					strIn = ENCODED_STRING()
					strIn['Character'] = ''
					valueTable += pack('<L', curHeapPtr)
					instanceHeap += strIn.getData()
					curHeapPtr = len(instanceHeap)
			
			ndTableLen = (len(properties) - 1) // 4 + 1
			packedNdTable = b''
			for i in range(ndTableLen):
				packedNdTable += pack('B', ndTable & 0xff)
				ndTable >>= 8
			
			instanceType['NdTable_ValueTable'] = packedNdTable + valueTable
			
			heapRecord = HEAP()
			heapRecord['HeapLength'] = len(instanceHeap) | 0x80000000
			heapRecord['HeapItem'] = instanceHeap
			instanceType['InstanceHeap'] = heapRecord
			instanceType['InstanceQualifierSet'] = b'\x04\x00\x00\x00\x01'
			instanceType['InstanceHeap']['HeapLength'] = len(instanceHeap) | 0x80000000
			instanceType['EncodingLength'] = len(instanceType)
			instanceType['CurrentClass'] = \
				self.encodingUnit['ObjectBlock']['ClassType']['CurrentClass']['ClassPart']
			
			instanceData['InstanceType'] = instanceType.getData()
			encodingUnit['ObjectBlock'] = instanceData
			encodingUnit['ObjectEncodingLength'] = len(instanceData)
			
			objRefCustomIn = OBJREF_CUSTOM()
			objRefCustomIn['iid'] = self._iid
			objRefCustomIn['clsid'] = CLSID_WbemClassObject
			objRefCustomIn['cbExtension'] = 0
			objRefCustomIn['ObjectReferenceSize'] = len(encodingUnit)
			objRefCustomIn['pObjectData'] = encodingUnit
			
			newObj = copy.deepcopy(self)
			newObj.set_objRef(objRefCustomIn.getData())
			newObj._process_interface(objRefCustomIn.getData())
			newObj.encodingUnit = ENCODING_UNIT(objRefCustomIn['pObjectData'])
			newObj.encodingUnit['ObjectBlock'].parseObject()
			newObj.createProperties(newObj.getProperties())
			
			return newObj
		else:
			return self
	
	def createProperties(self, properties):
		"""Create instance attributes from properties"""
		for property in properties:
			cimType = properties[property]['type'] & (~Inherited)
			
			if cimType == CIM_TYPE_ENUM.CIM_TYPE_OBJECT:
				if properties[property]['value'] is not None:
					objRef = OBJREF_CUSTOM()
					objRef['iid'] = self._iid
					objRef['clsid'] = CLSID_WbemClassObject
					objRef['cbExtension'] = 0
					objRef['ObjectReferenceSize'] = len(properties[property]['value'].getData())
					objRef['pObjectData'] = properties[property]['value']
					value = IWbemClassObject(
						INTERFACE(self.get_cinstance(), objRef.getData(), self.get_ipidRemUnknown(),
								  oxid=self.get_oxid(), target=self.get_target()))
				else:
					value = None
			elif cimType == CIM_TYPE_ENUM.CIM_ARRAY_OBJECT:
				if isinstance(properties[property]['value'], list):
					value = []
					for item in properties[property]['value']:
						objRef = OBJREF_CUSTOM()
						objRef['iid'] = self._iid
						objRef['clsid'] = CLSID_WbemClassObject
						objRef['cbExtension'] = 0
						objRef['ObjectReferenceSize'] = len(item.getData())
						objRef['pObjectData'] = item
						wbemClass = IWbemClassObject(
							INTERFACE(self.get_cinstance(), objRef.getData(), self.get_ipidRemUnknown(),
									  oxid=self.get_oxid(), target=self.get_target()))
						value.append(wbemClass)
				else:
					value = properties[property]['value']
			else:
				value = properties[property]['value']
			
			setattr(self, property, value)
	
	def _convert_value_for_dict(self, value):
		"""
		Convert a single value to a JSON-safe type.
		
		This method ensures any value can be safely serialized, converting
		unknown types to their string representation.
		"""
		try:
			# None passes through
			if value is None:
				return None
			
			# Basic JSON types pass through
			if isinstance(value, (bool, int, float, str)):
				return value
			
			# Handle nested IWbemClassObject instances
			if isinstance(value, IWbemClassObject):
				return value.to_dict()
			
			# Handle bytes
			if isinstance(value, bytes):
				try:
					return value.decode('utf-8')
				except (UnicodeDecodeError, AttributeError):
					return value.hex()
			
			# Handle lists/tuples
			if isinstance(value, (list, tuple)):
				return [self._convert_value_for_dict(item) for item in value]
			
			# Handle dicts
			if isinstance(value, dict):
				return {str(k): self._convert_value_for_dict(v) for k, v in value.items()}
			
			# Handle sets
			if isinstance(value, (set, frozenset)):
				return [self._convert_value_for_dict(item) for item in value]
			
			# Fallback: convert to string representation
			return str(value)
		
		except Exception:
			# Last resort: if anything fails, return a placeholder
			try:
				return f"<{type(value).__name__}>"
			except Exception:
				return "<unknown>"
	
	def to_dict(self) -> dict:
		"""
		Convert this WMI object to a dictionary.
		
		Always includes '__class__' key with the WMI class name, which is
		important when queries return items of different WMI classes
		(e.g., association queries or certain system queries).
		
		Recursively handles nested IWbemClassObject instances and arrays.
		All values are guaranteed to be JSON-serializable basic types.
		Unknown or complex types are converted to their string representation.
		
		Returns:
			Dictionary with '__class__' and property names as keys
		"""
		result = {}
		
		try:
			result['__class__'] = self.getClassName()
		except Exception:
			result['__class__'] = '<unknown>'
		
		try:
			properties = self.getProperties()
		except Exception:
			return result
		
		for prop_name, prop_info in properties.items():
			try:
				value = getattr(self, prop_name, None)
				result[prop_name] = self._convert_value_for_dict(value)
			except Exception:
				# If we can't get or convert a property, store a placeholder
				result[prop_name] = None
		
		return result
	
	def to_json(self, indent: int = None, **kwargs) -> str:
		"""
		Convert this WMI object to a JSON string.
		
		This method is guaranteed to return a valid JSON string and will never
		raise an exception. Any non-serializable values are converted to their
		string representation.
		
		Always includes '__class__' key with the WMI class name.
		Recursively handles nested IWbemClassObject instances and arrays.
		
		Args:
			indent: JSON indentation level (None for compact, 2 or 4 for pretty)
			**kwargs: Additional arguments passed to json.dumps()
		
		Returns:
			JSON string representation of the object (always valid JSON)
		"""
		try:
			data = self.to_dict()
		except Exception:
			# If to_dict fails completely, return minimal valid JSON
			data = {"__class__": "<unknown>", "__error__": "Failed to convert object"}
		
		# Failsafe JSON encoder - converts ANY unknown type to string
		def failsafe_serializer(obj):
			try:
				if isinstance(obj, bytes):
					try:
						return obj.decode('utf-8')
					except (UnicodeDecodeError, AttributeError):
						return obj.hex()
				return str(obj)
			except Exception:
				try:
					return f"<{type(obj).__name__}>"
				except Exception:
					return "<unknown>"
		
		try:
			return json.dumps(data, indent=indent, default=failsafe_serializer, **kwargs)
		except Exception:
			# Ultimate fallback - should never happen, but just in case
			try:
				# Try without the kwargs that might cause issues
				return json.dumps(data, indent=indent, default=failsafe_serializer)
			except Exception:
				# Return minimal valid JSON as absolute last resort
				return '{"__class__": "<unknown>", "__error__": "JSON serialization failed"}'
	
	def createMethods(self, classOrInstance, methods):
		"""Create callable methods on this object"""
		
		class FunctionPool:
			def __init__(self, function):
				self.function = function
			
			def __getitem__(self, item):
				return partial(self.function, item)
		
		@FunctionPool
		async def innerMethod(staticArgs, *args):
			classOrInstance = staticArgs[0]
			methodDefinition = staticArgs[1]
			iWbemServices = staticArgs[2]
			
			if methodDefinition.get('InParams') is not None:
				if len(args) != len(methodDefinition['InParams']):
					LOG.error("Function called with %d parameters instead of %d!" % (
						len(args), len(methodDefinition['InParams'])))
					return None, Exception("Parameter count mismatch")
				
				# Build input parameters
				encodingUnit = ENCODING_UNIT()
				inParams = OBJECT_BLOCK()
				inParams.structure += OBJECT_BLOCK.instanceType
				inParams['ObjectFlags'] = 2
				inParams['Decoration'] = b''
				
				instanceType = INSTANCE_TYPE()
				instanceType['CurrentClass'] = b''
				instanceType['InstanceQualifierSet'] = b'\x04\x00\x00\x00\x01'
				
				instanceHeap = b''
				valueTable = b''
				
				parametersClass = ENCODED_STRING()
				parametersClass['Character'] = '__PARAMETERS'
				instanceHeap += parametersClass.getData()
				curHeapPtr = len(instanceHeap)
				ndTable = 0
				
				for i, arg in enumerate(args):
					paramDefinition = list(methodDefinition['InParams'].values())[i]
					pType = paramDefinition['type'] & (~(CIM_ARRAY_FLAG | Inherited))
					
					if paramDefinition['type'] & CIM_ARRAY_FLAG:
						packStr = HEAPREF[:-2]
					else:
						packStr = CIM_TYPES_REF[pType][:-2]
					
					if paramDefinition['type'] & CIM_ARRAY_FLAG:
						if arg is None:
							valueTable += pack(packStr, 0)
						else:
							# Array handling
							arraySize = pack(HEAPREF[:-2], len(arg))
							valueTable += pack('<L', curHeapPtr)
							instanceHeap += arraySize
							for curVal in arg:
								instanceHeap += pack(packStr, curVal)
							curHeapPtr = len(instanceHeap)
					elif pType not in (CIM_TYPE_ENUM.CIM_TYPE_STRING,
									  CIM_TYPE_ENUM.CIM_TYPE_DATETIME,
									  CIM_TYPE_ENUM.CIM_TYPE_REFERENCE,
									  CIM_TYPE_ENUM.CIM_TYPE_OBJECT):
						valueTable += pack(packStr, arg if arg is not None else 0)
					elif pType == CIM_TYPE_ENUM.CIM_TYPE_OBJECT:
						if arg is None:
							valueTable += b'\x00' * 4
							ndTable |= IWbemClassObject.__ndEntry(i, True, True)
						else:
							valueTable += pack('<L', curHeapPtr)
							marshaledObject = arg.marshalMe()
							instanceHeap += pack('<L', marshaledObject['pObjectData']['ObjectEncodingLength'])
							instanceHeap += marshaledObject['pObjectData']['ObjectBlock'].getData()
							curHeapPtr = len(instanceHeap)
					else:
						strIn = ENCODED_STRING()
						if isinstance(arg, str):
							strIn['Encoded_String_Flag'] = 0x1
							strIn.structure = strIn.tunicode
							strIn['Character'] = arg.encode('utf-16le')
						else:
							strIn['Character'] = arg if arg else ''
						valueTable += pack('<L', curHeapPtr)
						instanceHeap += strIn.getData()
						curHeapPtr = len(instanceHeap)
				
				ndTableLen = (len(args) - 1) // 4 + 1
				packedNdTable = b''
				for i in range(ndTableLen):
					packedNdTable += pack('B', ndTable & 0xff)
					ndTable >>= 8
				
				instanceType['NdTable_ValueTable'] = packedNdTable + valueTable
				
				heapRecord = HEAP()
				heapRecord['HeapLength'] = len(instanceHeap) | 0x80000000
				heapRecord['HeapItem'] = instanceHeap
				instanceType['InstanceHeap'] = heapRecord
				
				# Set EncodingLength before CurrentClass (like impacket does)
				instanceType['EncodingLength'] = len(instanceType)
				
				# Use the original ClassPart from the method's InParams definition
				# This contains the parameter class definition (__PARAMETERS)
				# We need to set EncodingLength before assigning (like impacket does)
				inMethods = methodDefinition['InParamsRaw']['ClassType']['CurrentClass']['ClassPart']
				inMethods['ClassHeader']['EncodingLength'] = len(
					methodDefinition['InParamsRaw']['ClassType']['CurrentClass']['ClassPart'].getData())
				instanceType['CurrentClass'] = inMethods
				
				inParams['InstanceType'] = instanceType.getData()
				encodingUnit['ObjectBlock'] = inParams
				encodingUnit['ObjectEncodingLength'] = len(inParams)
				
				objRefCustomIn = OBJREF_CUSTOM()
				objRefCustomIn['iid'] = IID_IWbemClassObject
				objRefCustomIn['clsid'] = CLSID_WbemClassObject
				objRefCustomIn['cbExtension'] = 0
				objRefCustomIn['ObjectReferenceSize'] = len(encodingUnit)
				objRefCustomIn['pObjectData'] = encodingUnit
			else:
				objRefCustomIn = NULL
			
			try:
				LOG.debug(f"ExecMethod: classOrInstance={classOrInstance}, method={methodDefinition['name']}")
				LOG.debug(f"ExecMethod: pInParams is {'NULL' if objRefCustomIn is NULL else 'set'}")
				result, err = await iWbemServices.ExecMethod(
					classOrInstance, 
					methodDefinition['name'], 
					pInParams=objRefCustomIn
				)
				return result, err
			except Exception as e:
				if LOG.level == logging.DEBUG:
					import traceback
					traceback.print_exc()
				return None, e
		
		for methodName in methods:
			innerMethod.__name__ = methodName
			setattr(self, innerMethod.__name__, 
				   innerMethod[classOrInstance, methods[methodName], self.__iWbemServices])


class IWbemLoginClientID(IRemUnknown):
	"""WMI Login Client ID interface"""
	
	def __init__(self, interface):
		IRemUnknown.__init__(self, interface)
		self._iid = IID_IWbemLoginClientID
	
	async def SetClientInfo(self, wszClientMachine, lClientProcId=1234):
		"""Set client identification info"""
		request = IWbemLoginClientID_SetClientInfo()
		request['wszClientMachine'] = checkNullString(wszClientMachine)
		request['lClientProcId'] = lClientProcId
		request['lReserved'] = 0
		
		resp, err = await self.request(request, iid=self._iid, uuid=self.get_iPid())
		if err is not None:
			return None, err
		return resp, None


class IWbemLoginHelper(IRemUnknown):
	"""WMI Login Helper interface"""
	
	def __init__(self, interface):
		IRemUnknown.__init__(self, interface)
		self._iid = IID_IWbemLoginHelper


class IWbemCallResult(IRemUnknown):
	"""WMI Async Call Result interface"""
	
	def __init__(self, interface):
		IRemUnknown.__init__(self, interface)
		self._iid = IID_IWbemCallResult
	
	async def QueryInterface(self, iid):
		"""Query for another interface"""
		pass  # Not commonly used
	
	async def GetResultObject(self, lTimeout=WBEM_INFINITE):
		"""Get result object from async call"""
		request = IWbemCallResult_GetResultObject()
		request['lTimeout'] = lTimeout
		
		resp, err = await self.request(request, iid=self._iid, uuid=self.get_iPid())
		if err is not None:
			return None, err
		
		return IWbemClassObject(
			INTERFACE(self.get_cinstance(), b''.join(resp['ppResultObject']['abData']),
					  self.get_ipidRemUnknown(), target=self.get_target())), None
	
	async def GetResultString(self, lTimeout=WBEM_INFINITE):
		"""Get result string from async call"""
		request = IWbemCallResult_GetResultString()
		request['lTimeout'] = lTimeout
		
		resp, err = await self.request(request, iid=self._iid, uuid=self.get_iPid())
		if err is not None:
			return None, err
		return resp['pstrResultString'], None
	
	async def GetCallStatus(self, lTimeout=WBEM_INFINITE):
		"""Get call status"""
		request = IWbemCallResult_GetCallStatus()
		request['lTimeout'] = lTimeout
		
		resp, err = await self.request(request, iid=self._iid, uuid=self.get_iPid())
		if err is not None:
			return None, err
		return resp['plStatus'], None


class IEnumWbemClassObject(IRemUnknown):
	"""
	Enumerator for WMI query results.
	
	Allows iterating over objects returned from ExecQuery.
	"""
	
	def __init__(self, interface, iWbemServices=None):
		IRemUnknown.__init__(self, interface)
		self._iid = IID_IEnumWbemClassObject
		self.__iWbemServices = iWbemServices
	
	async def Reset(self):
		"""Reset enumeration to beginning"""
		request = IEnumWbemClassObject_Reset()
		
		resp, err = await self.request(request, iid=self._iid, uuid=self.get_iPid())
		if err is not None:
			return None, err
		return resp['ErrorCode'], None
	
	async def Next(self, lTimeout=WBEM_INFINITE, uCount=1):
		"""
		Get next object(s) from enumeration.
		
		Returns:
			(list[IWbemClassObject], error) - List of objects and any error.
			Returns ([], None) when enumeration is complete (WBEM_S_FALSE).
		"""
		request = IEnumWbemClassObject_Next()
		request['lTimeout'] = lTimeout
		request['uCount'] = uCount
		
		resp, err = await self.request(request, iid=self._iid, uuid=self.get_iPid())
		if err is not None:
			# WBEM_S_FALSE means "no more items" but the response may still
			# contain valid objects (the last partial batch). Similarly,
			# WBEM_S_TIMEDOUT may contain partial results.
			# Extract the packet from the error if available.
			error_code = getattr(err, 'error_code', None)
			if error_code in (WBEMSTATUS.WBEM_S_FALSE, WBEMSTATUS.WBEM_S_TIMEDOUT):
				packet = getattr(err, 'packet', None)
				if packet is not None:
					resp = packet
				else:
					# No packet - truly no more items
					return [], None
			else:
				return None, err
		
		interfaces = []
		for obj in resp['apObjects']:
			try:
				interfaces.append(IWbemClassObject(
					INTERFACE(self.get_cinstance(), b''.join(obj['abData']),
							  self.get_ipidRemUnknown(), oxid=self.get_oxid(),
							  target=self.get_target()),
					self.__iWbemServices))
			except Exception as e:
				LOG.debug(f'IEnumWbemClassObject.Next: Failed to parse object: {e}')
				continue
		
		return interfaces, None
	
	async def NextAsync(self, lTimeout, pSink):
		"""Async Next operation"""
		request = IEnumWbemClassObject_NextAsync()
		request['lTimeout'] = lTimeout
		request['pSink'] = pSink
		
		resp, err = await self.request(request, iid=self._iid, uuid=self.get_iPid())
		if err is not None:
			return None, err
		return resp, None
	
	async def Clone(self):
		"""Clone the enumerator"""
		request = IEnumWbemClassObject_Clone()
		
		resp, err = await self.request(request, iid=self._iid, uuid=self.get_iPid())
		if err is not None:
			return None, err
		
		return IEnumWbemClassObject(
			INTERFACE(self.get_cinstance(), b''.join(resp['ppEnum']['abData']),
					  self.get_ipidRemUnknown(), target=self.get_target()),
			self.__iWbemServices), None
	
	async def Skip(self, lTimeout, uCount):
		"""Skip a number of objects"""
		request = IEnumWbemClassObject_Skip()
		request['lTimeout'] = lTimeout
		request['uCount'] = uCount
		
		resp, err = await self.request(request, iid=self._iid, uuid=self.get_iPid())
		if err is not None:
			return None, err
		return resp, None
	
	def __aiter__(self):
		"""
		Async iterator support for streaming results.
		
		Memory-efficient way to iterate over large result sets.
		Each item is an IWbemClassObject instance.
		
		Usage:
			async for item in iEnum:
				print(item.to_dict())
				# or: print(item.Name, item.ProcessId)
		"""
		return self._AsyncIterator(self)
	
	class _AsyncIterator:
		"""Internal async iterator implementation"""
		
		def __init__(self, enum):
			self._enum = enum
			self._buffer = []
			self._exhausted = False
		
		def __aiter__(self):
			return self
		
		async def __anext__(self):
			# Return from buffer if available
			if self._buffer:
				return self._buffer.pop(0)
			
			# Check if enumeration is exhausted
			if self._exhausted:
				raise StopAsyncIteration
			
			# Fetch next batch
			try:
				items, err = await self._enum.Next(WBEM_INFINITE, 10)
				if err is not None or not items:
					self._exhausted = True
					raise StopAsyncIteration
				
				self._buffer = list(items)
				return self._buffer.pop(0)
			except StopAsyncIteration:
				raise
			except Exception as e:
				self._exhausted = True
				LOG.debug('IEnumWbemClassObject iterator error: %s' % e)
				raise
	
	async def FetchAll(self, limit: int = 1000, as_dict: bool = True, batch_size: int = 100):
		"""
		Fetch all (or up to limit) results from the enumeration.
		
		This is a convenience method for small to medium result sets.
		For large result sets, use the async iterator instead:
			async for item in iEnum:
				process(item)
		
		Args:
			limit: Maximum number of items to fetch (default 1000).
				   Set to None or 0 for unlimited (use with caution!).
			as_dict: If True, returns list of dicts (via to_dict()).
					If False, returns list of IWbemClassObject instances.
			batch_size: Number of items to fetch per RPC call (default 100).
		
		Returns:
			Tuple of (results: list, truncated: bool)
			- results: List of dicts or IWbemClassObject instances
			- truncated: True if limit was reached (more items may exist)
		
		Example:
			results, truncated = await iEnum.FetchAll(limit=500)
			if truncated:
				print("Warning: Results were truncated")
			for item in results:
				print(item['__class__'], item.get('Name'))
		"""
		results = []
		truncated = False
		effective_limit = limit if limit and limit > 0 else float('inf')
		
		while len(results) < effective_limit:
			# Calculate how many to fetch this batch
			remaining = effective_limit - len(results)
			fetch_count = min(batch_size, remaining) if remaining != float('inf') else batch_size
			
			try:
				items, err = await self.Next(WBEM_INFINITE, int(fetch_count))
				if err is not None or not items:
					break
				
				for item in items:
					if len(results) >= effective_limit:
						truncated = True
						break
					
					if as_dict:
						results.append(item.to_dict())
					else:
						results.append(item)
				
				# If we got fewer items than requested, enumeration is complete
				if len(items) < fetch_count:
					break
					
			except Exception:
				break
		
		# Check if there are more items (to set truncated flag)
		if len(results) >= effective_limit and effective_limit != float('inf'):
			# Try to peek if there are more
			try:
				peek_items, _ = await self.Next(WBEM_INFINITE, 1)
				if peek_items:
					truncated = True
			except Exception:
				pass
		
		return results, truncated


class IWbemServices(IRemUnknown):
	"""
	Main WMI Services interface.
	
	Provides access to WMI operations:
	- ExecQuery for WQL queries
	- GetObject for retrieving classes/instances
	- ExecMethod for invoking methods
	- DeleteInstance, PutInstance for instance management
	"""
	
	def __init__(self, interface):
		IRemUnknown.__init__(self, interface)
		self._iid = IID_IWbemServices
	
	async def OpenNamespace(self, strNamespace, lFlags=0, pCtx=NULL):
		"""Open a child namespace"""
		request = IWbemServices_OpenNamespace()
		request['strNamespace']['asData'] = strNamespace
		request['lFlags'] = lFlags
		request['pCtx'] = pCtx
		
		resp, err = await self.request(request, iid=self._iid, uuid=self.get_iPid())
		if err is not None:
			return None, err
		return resp, None
	
	async def CancelAsyncCall(self, IWbemObjectSink):
		"""Cancel an async call"""
		request = IWbemServices_CancelAsyncCall()
		request['IWbemObjectSink'] = IWbemObjectSink
		
		resp, err = await self.request(request, iid=self._iid, uuid=self.get_iPid())
		if err is not None:
			return None, err
		return resp['ErrorCode'], None
	
	async def QueryObjectSink(self):
		"""Query for object sink"""
		request = IWbemServices_QueryObjectSink()
		request['lFlags'] = 0
		
		resp, err = await self.request(request, iid=self._iid, uuid=self.get_iPid())
		if err is not None:
			return None, err
		
		return INTERFACE(self.get_cinstance(), b''.join(resp['ppResponseHandler']['abData']),
						self.get_ipidRemUnknown(), target=self.get_target()), None
	
	async def GetObject(self, strObjectPath, lFlags=0, pCtx=NULL):
		"""
		Get a WMI class definition or instance.
		
		Args:
			strObjectPath: Object path like 'Win32_Process' or 'Win32_Process.Handle=123'
			lFlags: Operation flags
			pCtx: Context object
		
		Returns:
			(IWbemClassObject, IWbemCallResult or NULL), error
		"""
		request = IWbemServices_GetObject()
		request['strObjectPath']['asData'] = strObjectPath
		request['lFlags'] = lFlags
		request['pCtx'] = pCtx
		
		resp, err = await self.request(request, iid=self._iid, uuid=self.get_iPid())
		if err is not None:
			return (None, None), err
		
		# NDRPOINTER auto-dereferences through pointer chain
		ppObject = IWbemClassObject(
			INTERFACE(self.get_cinstance(), b''.join(resp['ppObject']['abData']),
					  self.get_ipidRemUnknown(), oxid=self.get_oxid(),
					  target=self.get_target()),
			self)
		
		# Check if ppCallResult pointer is non-null by checking pointer value
		try:
			callResultData = resp['ppCallResult']['abData']
			ppcallResult = IWbemCallResult(
				INTERFACE(self.get_cinstance(), b''.join(callResultData),
						  self.get_ipidRemUnknown(), target=self.get_target()))
		except (KeyError, TypeError):
			# Null pointer - no call result
			ppcallResult = NULL
		
		return (ppObject, ppcallResult), None
	
	async def GetObjectAsync(self, strNamespace, lFlags=0, pCtx=NULL):
		"""Async GetObject"""
		request = IWbemServices_GetObjectAsync()
		request['strObjectPath']['asData'] = checkNullString(strNamespace)
		request['lFlags'] = lFlags
		request['pCtx'] = pCtx
		
		resp, err = await self.request(request, iid=self._iid, uuid=self.get_iPid())
		if err is not None:
			return None, err
		return resp, None
	
	async def PutClass(self, pObject, lFlags=0, pCtx=NULL):
		"""Register a class"""
		request = IWbemServices_PutClass()
		request['pObject'] = pObject
		request['lFlags'] = lFlags
		request['pCtx'] = pCtx
		
		resp, err = await self.request(request, iid=self._iid, uuid=self.get_iPid())
		if err is not None:
			return None, err
		return resp, None
	
	async def DeleteClass(self, strClass, lFlags=0, pCtx=NULL):
		"""Delete a class"""
		request = IWbemServices_DeleteClass()
		request['strClass']['asData'] = checkNullString(strClass)
		request['lFlags'] = lFlags
		request['pCtx'] = pCtx
		
		resp, err = await self.request(request, iid=self._iid, uuid=self.get_iPid())
		if err is not None:
			return None, err
		return resp, None
	
	async def CreateClassEnum(self, strSuperClass, lFlags=0, pCtx=NULL):
		"""Enumerate classes"""
		request = IWbemServices_CreateClassEnum()
		request['strSuperClass']['asData'] = strSuperClass
		request['lFlags'] = lFlags
		request['pCtx'] = pCtx
		
		resp, err = await self.request(request, iid=self._iid, uuid=self.get_iPid())
		if err is not None:
			return None, err
		
		return IEnumWbemClassObject(
			INTERFACE(self.get_cinstance(), b''.join(resp['ppEnum']['abData']),
					  self.get_ipidRemUnknown(), target=self.get_target()),
			self), None
	
	async def PutInstance(self, pInst, lFlags=0, pCtx=NULL):
		"""Create or update an instance"""
		request = IWbemServices_PutInstance()
		if isinstance(pInst, IWbemClassObject):
			pInst = pInst.marshalMe()
		request['pInst']['ulCntData'] = len(pInst.getData())
		request['pInst']['abData'] = list(pInst.getData())
		request['lFlags'] = lFlags
		request['pCtx'] = pCtx
		
		resp, err = await self.request(request, iid=self._iid, uuid=self.get_iPid())
		if err is not None:
			return None, err
		
		return IWbemCallResult(
			INTERFACE(self.get_cinstance(), b''.join(resp['ppCallResult']['abData']),
					  self.get_ipidRemUnknown(), target=self.get_target())), None
	
	async def DeleteInstance(self, strObjectPath, lFlags=0, pCtx=NULL):
		"""Delete an instance"""
		request = IWbemServices_DeleteInstance()
		request['strObjectPath']['asData'] = checkNullString(strObjectPath)
		request['lFlags'] = lFlags
		request['pCtx'] = pCtx
		
		resp, err = await self.request(request, iid=self._iid, uuid=self.get_iPid())
		if err is not None:
			return None, err
		
		return IWbemCallResult(
			INTERFACE(self.get_cinstance(), b''.join(resp['ppCallResult']['abData']),
					  self.get_ipidRemUnknown(), target=self.get_target())), None
	
	async def CreateInstanceEnum(self, strSuperClass, lFlags=0, pCtx=NULL):
		"""Enumerate instances of a class"""
		request = IWbemServices_CreateInstanceEnum()
		request['strSuperClass']['asData'] = strSuperClass
		request['lFlags'] = lFlags
		request['pCtx'] = pCtx
		
		resp, err = await self.request(request, iid=self._iid, uuid=self.get_iPid())
		if err is not None:
			return None, err
		
		return IEnumWbemClassObject(
			INTERFACE(self.get_cinstance(), b''.join(resp['ppEnum']['abData']),
					  self.get_ipidRemUnknown(), target=self.get_target()),
			self), None
	
	async def ExecQuery(self, strQuery, lFlags=0, pCtx=NULL):
		"""
		Execute a WQL query.
		
		Args:
			strQuery: WQL query string like 'SELECT * FROM Win32_Process'
			lFlags: Operation flags
			pCtx: Context object
		
		Returns:
			(IEnumWbemClassObject, error) - Enumerator for results
		"""
		request = IWbemServices_ExecQuery()
		request['strQueryLanguage']['asData'] = checkNullString('WQL')
		request['strQuery']['asData'] = checkNullString(strQuery)
		request['lFlags'] = lFlags
		request['pCtx'] = pCtx
		
		resp, err = await self.request(request, iid=self._iid, uuid=self.get_iPid())
		if err is not None:
			return None, err
		
		return IEnumWbemClassObject(
			INTERFACE(self.get_cinstance(), b''.join(resp['ppEnum']['abData']),
					  self.get_ipidRemUnknown(), target=self.get_target()),
			self), None
	
	async def ExecQueryAsync(self, strQuery, lFlags=0, pCtx=NULL):
		"""Async query execution"""
		request = IWbemServices_ExecQueryAsync()
		request['strQueryLanguage']['asData'] = checkNullString('WQL')
		request['strQuery']['asData'] = checkNullString(strQuery)
		request['lFlags'] = lFlags
		request['pCtx'] = pCtx
		
		resp, err = await self.request(request, iid=self._iid, uuid=self.get_iPid())
		if err is not None:
			return None, err
		return resp, None
	
	async def ExecNotificationQuery(self, strQuery, lFlags=0, pCtx=NULL):
		"""Execute a notification query for events"""
		request = IWbemServices_ExecNotificationQuery()
		request['strQueryLanguage']['asData'] = checkNullString('WQL')
		request['strQuery']['asData'] = checkNullString(strQuery)
		request['lFlags'] = lFlags
		request['pCtx'] = pCtx
		
		resp, err = await self.request(request, iid=self._iid, uuid=self.get_iPid())
		if err is not None:
			return None, err
		
		return IEnumWbemClassObject(
			INTERFACE(self.get_cinstance(), b''.join(resp['ppEnum']['abData']),
					  self.get_ipidRemUnknown(), target=self.get_target()),
			self), None
	
	async def ExecMethod(self, strObjectPath, strMethodName, lFlags=0, pCtx=NULL,
						pInParams=NULL, ppOutParams=NULL):
		"""
		Execute a method on a WMI object.
		
		Args:
			strObjectPath: Object path like 'Win32_Process' or 'Win32_Process.Handle=123'
			strMethodName: Method name to invoke
			lFlags: Operation flags
			pCtx: Context object
			pInParams: Input parameters (OBJREF_CUSTOM or marshaled object)
			ppOutParams: Output parameters placeholder
		
		Returns:
			(IWbemClassObject with out params, error)
		"""
		request = IWbemServices_ExecMethod()
		request['strObjectPath']['asData'] = checkNullString(strObjectPath)
		request['strMethodName']['asData'] = checkNullString(strMethodName)
		request['lFlags'] = lFlags
		request['pCtx'] = pCtx
		
		if pInParams is NULL:
			request['pInParams'] = pInParams
		else:
			pInParamsData = pInParams.getData()
			request['pInParams']['ulCntData'] = len(pInParamsData)
			request['pInParams']['abData'] = list(pInParamsData)
		
		request.fields['ppCallResult'] = NULL
		if ppOutParams is NULL:
			request.fields['ppOutParams'].fields['Data'] = NULL
		else:
			ppOutParamsData = ppOutParams.getData()
			request['ppOutParams']['ulCntData'] = len(ppOutParamsData)
			request['ppOutParams']['abData'] = list(ppOutParamsData)
		
		resp, err = await self.request(request, iid=self._iid, uuid=self.get_iPid())
		if err is not None:
			return None, err
		
		return IWbemClassObject(
			INTERFACE(self.get_cinstance(), b''.join(resp['ppOutParams']['abData']),
					  self.get_ipidRemUnknown(), oxid=self.get_oxid(),
					  target=self.get_target())), None
	
	async def ExecMethodAsync(self, strObjectPath, strMethodName, lFlags=0, pCtx=NULL,
							 pInParams=NULL):
		"""Async method execution"""
		request = IWbemServices_ExecMethodAsync()
		request['strObjectPath']['asData'] = checkNullString(strObjectPath)
		request['strMethodName']['asData'] = checkNullString(strMethodName)
		request['lFlags'] = lFlags
		request['pCtx'] = pCtx
		request['pInParams'] = pInParams
		
		resp, err = await self.request(request, iid=self._iid, uuid=self.get_iPid())
		if err is not None:
			return None, err
		return resp, None


class IWbemLevel1Login(IRemUnknown):
	"""
	WMI Level 1 Login interface.
	
	Primary entry point for WMI connections.
	Use NTLMLogin to authenticate and get IWbemServices.
	"""
	
	def __init__(self, interface):
		IRemUnknown.__init__(self, interface)
		self._iid = IID_IWbemLevel1Login
	
	async def EstablishPosition(self):
		"""Establish position (reserved)"""
		request = IWbemLevel1Login_EstablishPosition()
		request['reserved1'] = NULL
		request['reserved2'] = 0
		
		resp, err = await self.request(request, iid=self._iid, uuid=self.get_iPid())
		if err is not None:
			return None, err
		return resp['LocaleVersion'], None
	
	async def RequestChallenge(self):
		"""Request challenge (reserved)"""
		request = IWbemLevel1Login_RequestChallenge()
		request['reserved1'] = NULL
		request['reserved2'] = NULL
		
		resp, err = await self.request(request, iid=self._iid, uuid=self.get_iPid())
		if err is not None:
			return None, err
		return resp['reserved3'], None
	
	async def WBEMLogin(self):
		"""WBEM Login (reserved, not implemented)"""
		request = IWbemLevel1Login_WBEMLogin()
		request['reserved1'] = NULL
		request['reserved2'] = NULL
		request['reserved3'] = 0
		request['reserved4'] = NULL
		
		resp, err = await self.request(request, iid=self._iid, uuid=self.get_iPid())
		if err is not None:
			return None, err
		return resp['reserved5'], None
	
	async def NTLMLogin(self, wszNetworkResource, wszPreferredLocale=NULL, pCtx=NULL):
		"""
		Login to WMI namespace using NTLM authentication.
		
		Args:
			wszNetworkResource: Namespace path like '//./root/cimv2' or '\\\\server\\root\\cimv2'
			wszPreferredLocale: Locale preference (usually NULL)
			pCtx: Context object (usually NULL)
		
		Returns:
			(IWbemServices, error) - Services interface for WMI operations
		"""
		import traceback
		from aiosmb import logger
		
		def safe_repr(obj):
			"""Safely convert object to string for logging (handles impacket structures)"""
			if obj is NULL:
				return 'NULL'
			if hasattr(obj, 'dump'):
				# Impacket structure - use dump() but capture output
				import io
				import sys
				old_stdout = sys.stdout
				sys.stdout = io.StringIO()
				try:
					obj.dump()
					return sys.stdout.getvalue().strip() or repr(obj)
				except:
					return f'<{type(obj).__name__}>'
				finally:
					sys.stdout = old_stdout
			try:
				return repr(obj)
			except:
				return f'<{type(obj).__name__}>'
		
		logger.debug('NTLMLogin called with:')
		logger.debug(f'  wszNetworkResource: {safe_repr(wszNetworkResource)}')
		logger.debug(f'  wszPreferredLocale: {safe_repr(wszPreferredLocale)}')
		logger.debug(f'  pCtx: {safe_repr(pCtx)}')
		logger.debug(f'  self._iid: {self._iid.hex() if isinstance(self._iid, bytes) else self._iid}')
		logger.debug(f'  self.get_iPid(): {self.get_iPid().hex() if isinstance(self.get_iPid(), bytes) else self.get_iPid()}')
		logger.debug(f'  self.get_cinstance(): {type(self.get_cinstance()).__name__}')
		
		if self.get_cinstance() is not None:
			cinstance = self.get_cinstance()
			orpc = cinstance.get_ORPCthis()
			logger.debug(f'  cinstance.get_ORPCthis(): {type(orpc).__name__ if orpc else None}')
			if orpc is not None and hasattr(orpc, 'fields'):
				logger.debug(f'  ORPCthis fields: {list(orpc.fields.keys())}')
		
		try:
			request = IWbemLevel1Login_NTLMLogin()
			logger.debug(f'  Request created: {type(request).__name__}')
			if hasattr(request, 'fields'):
				logger.debug(f'  Request fields: {list(request.fields.keys())}')
			
			request['wszNetworkResource'] = checkNullString(wszNetworkResource)
			request['wszPreferredLocale'] = checkNullString(wszPreferredLocale) if wszPreferredLocale != NULL else NULL
			request['lFlags'] = 0
			request['pCtx'] = pCtx
			
			logger.debug('  Request populated, calling self.request()')
			
			resp, err = await self.request(request, iid=self._iid, uuid=self.get_iPid())
			if err is not None:
				logger.error(f'NTLMLogin failed: {type(err).__name__}: {err}')
				logger.debug(f'Traceback:\n{traceback.format_exc()}')
				return None, Exception(f'NTLMLogin failed: {err}')
			
			logger.debug('NTLMLogin succeeded, creating IWbemServices')
			return IWbemServices(
				INTERFACE(self.get_cinstance(), b''.join(resp['ppNamespace']['abData']),
						  self.get_ipidRemUnknown(), target=self.get_target())), None
						  
		except Exception as e:
			logger.error(f'NTLMLogin exception: {type(e).__name__}: {err}')
			logger.debug(f'Traceback:\n{traceback.format_exc()}')
			return None, e

from aiosmb.dcerpc.v5.common.connection.authentication import DCERPCAuth
from aiosmb.dcerpc.v5.common.connection.target import DCERPCTarget
from aiosmb.dcerpc.v5.dcom.connection import DCOMConnection
from aiosmb.dcerpc.v5.dcom.wmi import IWbemServices, CLSID_WbemLevel1Login, IID_IWbemLevel1Login
from aiosmb.connection import SMBConnection

class WMIConnectionFactory:
	def __init__(self, credential:DCERPCAuth, target:DCERPCTarget):
		self.credential = credential
		self.target = target
	
	@staticmethod
	def from_smbconnection(self, smbconnection:SMBConnection):
		credential = DCERPCAuth.from_smb_gssapi(smbconnection.gssapi)
		target = DCERPCTarget.from_smbconnection(smbconnection)
		return WMIConnectionFactory(credential, target)

	def get_target(self):
		return copy.deepcopy(self.target)

	def get_credential(self):
		return copy.deepcopy(self.credential)


	async def get_connection_newtarget(self, ip:str, hostname:str):
		try:
			target = self.get_target()
			target.ip = ip
			target.hostname = hostname
			factory = WMIConnectionFactory(self.get_credential(), target)
			return await factory.get_connection()
		except Exception as e:
			return None, e
	
	async def get_connection(self):
		try:
			domain = self.credential.domain
			if domain is None:
				domain = self.target.domain
			if domain is None:
				domain = ''
			
			dcom = DCOMConnection(
				target=self.get_target().get_ip_or_hostname(),
				auth=self.get_credential(),
				proxies=self.target.proxies,
				dc_ip=self.target.dc_ip,
				domain=domain
			)
			_, err = await dcom.connect()
			if err is not None:
				raise err

			return WMIConnection(dcom), None
		except Exception as e:
			return None, e

class WMIConnection:
	def __init__(self, dcom:DCOMConnection):
		self.dcom = dcom
		self.iInterface: IRemUnknown = None
		self.iWbemLevel1Login: IWbemLevel1Login = None
		self.iWbemServices: IWbemServices = None
	
	async def __aenter__(self):
		return self
	
	async def __aexit__(self, exc_type, exc_val, exc_tb):
		await self.disconnect()
		return True, None
	
	async def login(self, namespace:str = '//./root/cimv2'):
		try:
			if namespace is None or namespace == '':
				namespace = '//./root/cimv2'
			self.iInterface, err = await self.dcom.CoCreateInstanceEx(
				CLSID_WbemLevel1Login,
				IID_IWbemLevel1Login
			)
			if err is not None:
				raise err
			
			self.iWbemLevel1Login = IWbemLevel1Login(self.iInterface)
			# Login to WMI namespace
			self.iWbemServices, err = await self.iWbemLevel1Login.NTLMLogin(
				namespace,
				NULL,
				NULL
			)
			if err is not None:
				raise err

			return True, None
		except Exception as e:
			return None, e
		
		finally:
			if self.iWbemLevel1Login is not None:
				await self.iWbemLevel1Login.RemRelease()
	
	async def disconnect(self):
		try:
			if self.iWbemServices is not None:
				await self.iWbemServices.RemRelease()
			if self.iWbemLevel1Login is not None:
				await self.iWbemLevel1Login.RemRelease()
			if self.iInterface is not None:
				await self.iInterface.RemRelease()
			return True, None
		except Exception as e:
			return False, e
	
	async def query(self, query:str, as_dict:bool = True):
		try:
			iEnum, err = await self.iWbemServices.ExecQuery(query)
			if err is not None:
				raise err
			async with iEnum:
				async for item in iEnum:
					if as_dict:
						yield item.to_dict(), None
					else:
						yield item, None
		except Exception as e:
			yield None, e
