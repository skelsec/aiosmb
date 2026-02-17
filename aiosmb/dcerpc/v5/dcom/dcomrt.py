# Async DCOM implementation for aiosmb
# Based on [MS-DCOM] Interface specification
#
# Ported from impacket with modifications for async/await patterns
# Original impacket author: Alberto Solino (@agsolino)
#

from struct import pack, unpack

from aiosmb.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT, NDRPOINTER, NDRUniConformantArray, NDRTLSTRUCT, UNKNOWNDATA
from aiosmb.dcerpc.v5.dtypes import LPWSTR, ULONGLONG, HRESULT, GUID, USHORT, WSTR, DWORD, LPLONG, LONG, PGUID, ULONG, \
    UUID, WIDESTR, NULL
from aiosmb.dcerpc.v5 import hresult_errors
from aiosmb.dcerpc.v5.uuid import string_to_bin, uuidtup_to_bin, generate
from aiosmb.dcerpc.v5.rpcrt import TypeSerialization1, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_NONE, \
    RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_WINNT, DCERPCException

# Well-known CLSIDs
CLSID_ActivationContextInfo   = string_to_bin('000001a5-0000-0000-c000-000000000046')
CLSID_ActivationPropertiesIn  = string_to_bin('00000338-0000-0000-c000-000000000046')
CLSID_ActivationPropertiesOut = string_to_bin('00000339-0000-0000-c000-000000000046')
CLSID_CONTEXT_EXTENSION       = string_to_bin('00000334-0000-0000-c000-000000000046')
CLSID_ContextMarshaler        = string_to_bin('0000033b-0000-0000-c000-000000000046')
CLSID_ERROR_EXTENSION         = string_to_bin('0000031c-0000-0000-c000-000000000046')
CLSID_ErrorObject             = string_to_bin('0000031b-0000-0000-c000-000000000046')
CLSID_InstanceInfo            = string_to_bin('000001ad-0000-0000-c000-000000000046')
CLSID_InstantiationInfo       = string_to_bin('000001ab-0000-0000-c000-000000000046')
CLSID_PropsOutInfo            = string_to_bin('00000339-0000-0000-c000-000000000046')
CLSID_ScmReplyInfo            = string_to_bin('000001b6-0000-0000-c000-000000000046')
CLSID_ScmRequestInfo          = string_to_bin('000001aa-0000-0000-c000-000000000046')
CLSID_SecurityInfo            = string_to_bin('000001a6-0000-0000-c000-000000000046')
CLSID_ServerLocationInfo      = string_to_bin('000001a4-0000-0000-c000-000000000046')
CLSID_SpecialSystemProperties = string_to_bin('000001b9-0000-0000-c000-000000000046')

# Well-known IIDs
IID_IActivation               = uuidtup_to_bin(('4d9f4ab8-7d1c-11cf-861e-0020af6e7c57','0.0'))
IID_IActivationPropertiesIn   = uuidtup_to_bin(('000001A2-0000-0000-C000-000000000046','0.0'))
IID_IActivationPropertiesOut  = uuidtup_to_bin(('000001A3-0000-0000-C000-000000000046','0.0'))
IID_IContext                  = uuidtup_to_bin(('000001c0-0000-0000-C000-000000000046','0.0'))
IID_IObjectExporter           = uuidtup_to_bin(('99fcfec4-5260-101b-bbcb-00aa0021347a','0.0'))
IID_IRemoteSCMActivator       = uuidtup_to_bin(('000001A0-0000-0000-C000-000000000046','0.0'))
IID_IRemUnknown               = uuidtup_to_bin(('00000131-0000-0000-C000-000000000046','0.0'))
IID_IRemUnknown2              = uuidtup_to_bin(('00000143-0000-0000-C000-000000000046','0.0'))
IID_IUnknown                  = uuidtup_to_bin(('00000000-0000-0000-C000-000000000046','0.0'))
IID_IClassFactory             = uuidtup_to_bin(('00000001-0000-0000-C000-000000000046','0.0'))

# Protocol Tower Identifiers from [c706] Annex I
CYCLONETOWERID_OSI_TP4 = 0x05
TOWERID_OSI_CLNS = 0x06
TOWERID_DOD_TCP = 0x0007
TOWERID_DOD_UDP = 0x08
TOWERID_DOD_IP = 0x09
TOWERID_RPC_connectionless = 0x0a
TOWERID_RPC_connectionoriented = 0x0b
TOWERID_DNA_Session_Control = 0x02
TOWERID_DNA_Session_Control_V3 = 0x03
TOWERID_DNA_NSP_Transport = 0x04
TOWERID_DNA_Routing = 0x06
TOWERID_Named_Pipes = 0x10
TOWERID_NetBIOS_11 = 0x11
TOWERID_NetBEUI = 0x12
TOWERID_Netware_SPX = 0x13
TOWERID_Netware_IPX = 0x14
TOWERID_Appletalk_Stream = 0x16
TOWERID_Appletalk_Datagram = 0x17
TOWERID_Appletalk = 0x18
TOWERID_NetBIOS_19 = 0x19
TOWERID_VINES_SPP = 0x1A
TOWERID_VINES_IPC = 0x1B
TOWERID_StreetTalk = 0x1C
TOWERID_Unix_Domain_socket = 0x20
TOWERID_null = 0x21
TOWERID_NetBIOS_22 = 0x22


class DCOMSessionError(DCERPCException):
    """DCOM-specific session error"""
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__(self):
        if self.error_code in hresult_errors.ERROR_MESSAGES:
            error_msg_short = hresult_errors.ERROR_MESSAGES[self.error_code][0]
            error_msg_verbose = hresult_errors.ERROR_MESSAGES[self.error_code][1]
            return 'DCOM SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'DCOM SessionError: unknown error code: 0x%x' % self.error_code

# Alias for compatibility with DCE/RPC connection error handling
DCERPCSessionError = DCOMSessionError


################################################################################
# CONSTANTS
################################################################################

# 2.2.1 OID
OID = ULONGLONG

class OID_ARRAY(NDRUniConformantArray):
    item = OID

class POID_ARRAY(NDRPOINTER):
    referent = (
        ('Data', OID_ARRAY),
    )

# 2.2.2 SETID
SETID = ULONGLONG

# 2.2.4 error_status_t
error_status_t = ULONG

# 2.2.6 CID
CID = GUID

# 2.2.7 CLSID
CLSID = GUID

# 2.2.8 IID
IID = GUID
PIID = PGUID

# 2.2.9 IPID
IPID = GUID

# 2.2.10 OXID
OXID = ULONGLONG

# 2.2.18 OBJREF flags
FLAGS_OBJREF_STANDARD = 0x00000001
FLAGS_OBJREF_HANDLER  = 0x00000002
FLAGS_OBJREF_CUSTOM   = 0x00000004
FLAGS_OBJREF_EXTENDED = 0x00000008

# 2.2.18.1 STDOBJREF flags
SORF_NOPING = 0x00001000

# 2.2.20 Context
CTXMSHLFLAGS_BYVAL = 0x00000002

# 2.2.20.1 PROPMARSHALHEADER flags
CPFLAG_PROPAGATE = 0x00000001
CPFLAG_EXPOSE    = 0x00000002
CPFLAG_ENVOY     = 0x00000004

# 2.2.22.2.1 InstantiationInfoData flags
ACTVFLAGS_DISABLE_AAA            = 0x00000002
ACTVFLAGS_ACTIVATE_32_BIT_SERVER = 0x00000004
ACTVFLAGS_ACTIVATE_64_BIT_SERVER = 0x00000008
ACTVFLAGS_NO_FAILURE_LOG         = 0x00000020

# 2.2.22.2.2 SpecialPropertiesData flags
SPD_FLAG_USE_CONSOLE_SESSION  = 0x00000001

# 2.2.28.1 IDL Range Constants
MAX_REQUESTED_INTERFACES = 0x8000
MAX_REQUESTED_PROTSEQS   = 0x8000
MIN_ACTPROP_LIMIT        = 1
MAX_ACTPROP_LIMIT        = 10


################################################################################
# STRUCTURES
################################################################################

class handle_t(NDRSTRUCT):
    structure = (
        ('context_handle_attributes', ULONG),
        ('context_handle_uuid', UUID),
    )

    def __init__(self, data=None, isNDR64=False):
        NDRSTRUCT.__init__(self, data, isNDR64)
        self['context_handle_uuid'] = b'\x00' * 16

    def isNull(self):
        return self['context_handle_uuid'] == b'\x00' * 16


# 2.2.11 COMVERSION
class COMVERSION(NDRSTRUCT):
    default_major_version = 5
    default_minor_version = 7

    structure = (
        ('MajorVersion', USHORT),
        ('MinorVersion', USHORT),
    )

    @classmethod
    def set_default_version(cls, major_version=None, minor_version=None):
        if major_version is not None:
            cls.default_major_version = major_version
        if minor_version is not None:
            cls.default_minor_version = minor_version

    def __init__(self, data=None, isNDR64=False):
        NDRSTRUCT.__init__(self, data, isNDR64)
        if data is None:
            self['MajorVersion'] = self.default_major_version
            self['MinorVersion'] = self.default_minor_version


class PCOMVERSION(NDRPOINTER):
    referent = (
        ('Data', COMVERSION),
    )


# 2.2.13.1 ORPC_EXTENT
class BYTE_ARRAY(NDRUniConformantArray):
    item = 'c'


class ORPC_EXTENT(NDRSTRUCT):
    structure = (
        ('id', GUID),
        ('size', ULONG),
        ('data', BYTE_ARRAY),
    )


# 2.2.13.2 ORPC_EXTENT_ARRAY
class PORPC_EXTENT(NDRPOINTER):
    referent = (
        ('Data', ORPC_EXTENT),
    )


class EXTENT_ARRAY(NDRUniConformantArray):
    item = PORPC_EXTENT


class PEXTENT_ARRAY(NDRPOINTER):
    referent = (
        ('Data', EXTENT_ARRAY),
    )


class ORPC_EXTENT_ARRAY(NDRSTRUCT):
    structure = (
        ('size', ULONG),
        ('reserved', ULONG),
        ('extent', PEXTENT_ARRAY),
    )


class PORPC_EXTENT_ARRAY(NDRPOINTER):
    referent = (
        ('Data', ORPC_EXTENT_ARRAY),
    )


# 2.2.13.3 ORPCTHIS
class ORPCTHIS(NDRSTRUCT):
    structure = (
        ('version', COMVERSION),
        ('flags', ULONG),
        ('reserved1', ULONG),
        ('cid', CID),
        ('extensions', PORPC_EXTENT_ARRAY),
    )


# 2.2.13.4 ORPCTHAT
class ORPCTHAT(NDRSTRUCT):
    structure = (
        ('flags', ULONG),
        ('extensions', PORPC_EXTENT_ARRAY),
    )


# 2.2.14 MInterfacePointer
class MInterfacePointer(NDRSTRUCT):
    structure = (
        ('ulCntData', ULONG),
        ('abData', BYTE_ARRAY),
    )


# 2.2.15 PMInterfacePointerInternal
class PMInterfacePointerInternal(NDRPOINTER):
    referent = (
        ('Data', MInterfacePointer),
    )


# 2.2.16 PMInterfacePointer
class PMInterfacePointer(NDRPOINTER):
    referent = (
        ('Data', MInterfacePointer),
    )


class PPMInterfacePointer(NDRPOINTER):
    referent = (
        ('Data', PMInterfacePointer),
    )


# 2.2.18 OBJREF
class OBJREF(NDRSTRUCT):
    commonHdr = (
        ('signature', ULONG),
        ('flags', ULONG),
        ('iid', GUID),
    )

    def __init__(self, data=None, isNDR64=False):
        NDRSTRUCT.__init__(self, data, isNDR64)
        if data is None:
            self['signature'] = 0x574F454D  # 'MEOW'


# 2.2.18.1 STDOBJREF
class STDOBJREF(NDRSTRUCT):
    structure = (
        ('flags', ULONG),
        ('cPublicRefs', ULONG),
        ('oxid', OXID),
        ('oid', OID),
        ('ipid', IPID),
    )


# 2.2.18.4 OBJREF_STANDARD
class OBJREF_STANDARD(OBJREF):
    structure = (
        ('std', STDOBJREF),
        ('saResAddr', ':'),
    )

    def __init__(self, data=None, isNDR64=False):
        OBJREF.__init__(self, data, isNDR64)
        if data is None:
            self['flags'] = FLAGS_OBJREF_STANDARD


# 2.2.18.5 OBJREF_HANDLER
class OBJREF_HANDLER(OBJREF):
    structure = (
        ('std', STDOBJREF),
        ('clsid', CLSID),
        ('saResAddr', ':'),
    )

    def __init__(self, data=None, isNDR64=False):
        OBJREF.__init__(self, data, isNDR64)
        if data is None:
            self['flags'] = FLAGS_OBJREF_HANDLER


# 2.2.18.6 OBJREF_CUSTOM
class OBJREF_CUSTOM(OBJREF):
    structure = (
        ('clsid', CLSID),
        ('cbExtension', ULONG),
        ('ObjectReferenceSize', ULONG),
        ('pObjectData', ':'),
    )

    def __init__(self, data=None, isNDR64=False):
        OBJREF.__init__(self, data, isNDR64)
        if data is None:
            self['flags'] = FLAGS_OBJREF_CUSTOM


# 2.2.18.8 DATAELEMENT
class DATAELEMENT(NDRSTRUCT):
    structure = (
        ('dataID', GUID),
        ('cbSize', ULONG),
        ('cbRounded', ULONG),
        ('Data', ':'),
    )


class DUALSTRINGARRAYPACKED(NDRSTRUCT):
    structure = (
        ('wNumEntries', USHORT),
        ('wSecurityOffset', USHORT),
        ('aStringArray', ':'),
    )

    def getDataLen(self, data, offset=0):
        return self['wNumEntries'] * 2


# 2.2.18.7 OBJREF_EXTENDED
class OBJREF_EXTENDED(OBJREF):
    structure = (
        ('std', STDOBJREF),
        ('Signature1', ULONG),
        ('saResAddr', DUALSTRINGARRAYPACKED),
        ('nElms', ULONG),
        ('Signature2', ULONG),
        ('ElmArray', DATAELEMENT),
    )

    def __init__(self, data=None, isNDR64=False):
        OBJREF.__init__(self, data, isNDR64)
        if data is None:
            self['flags'] = FLAGS_OBJREF_EXTENDED
            self['Signature1'] = 0x4E535956
            self['Signature2'] = 0x4E535956
            self['nElms'] = 0


# 2.2.19 DUALSTRINGARRAY
class USHORT_ARRAY(NDRUniConformantArray):
    item = '<H'


class PUSHORT_ARRAY(NDRPOINTER):
    referent = (
        ('Data', USHORT_ARRAY),
    )


class DUALSTRINGARRAY(NDRSTRUCT):
    structure = (
        ('wNumEntries', USHORT),
        ('wSecurityOffset', USHORT),
        ('aStringArray', USHORT_ARRAY),
    )


class PDUALSTRINGARRAY(NDRPOINTER):
    referent = (
        ('Data', DUALSTRINGARRAY),
    )


# 2.2.19.3 STRINGBINDING
class STRINGBINDING(NDRSTRUCT):
    structure = (
        ('wTowerId', USHORT),
        ('aNetworkAddr', WIDESTR),
    )


# 2.2.19.4 SECURITYBINDING
class SECURITYBINDING(NDRSTRUCT):
    structure = (
        ('wAuthnSvc', USHORT),
        ('Reserved', USHORT),
        ('aPrincName', WIDESTR),
    )


# 2.2.20.1 PROPMARSHALHEADER
class PROPMARSHALHEADER(NDRSTRUCT):
    structure = (
        ('clsid', CLSID),
        ('policyId', GUID),
        ('flags', ULONG),
        ('cb', ULONG),
        ('ctxProperty', ':'),
    )


class PROPMARSHALHEADER_ARRAY(NDRUniConformantArray):
    item = PROPMARSHALHEADER


# 2.2.20 Context
class Context(NDRSTRUCT):
    structure = (
        ('MajorVersion', USHORT),
        ('MinVersion', USHORT),
        ('ContextId', GUID),
        ('Flags', ULONG),
        ('Reserved', ULONG),
        ('dwNumExtents', ULONG),
        ('cbExtents', ULONG),
        ('MshlFlags', ULONG),
        ('Count', ULONG),
        ('Frozen', ULONG),
        ('PropMarshalHeader', PROPMARSHALHEADER_ARRAY),
    )


# 2.2.21.3 ErrorInfoString
class ErrorInfoString(NDRSTRUCT):
    structure = (
        ('dwMax', ULONG),
        ('dwOffSet', ULONG),
        ('dwActual', IID),
        ('Name', WSTR),
    )


# 2.2.21.2 Custom-Marshaled Error Information Format
class ORPC_ERROR_INFORMATION(NDRSTRUCT):
    structure = (
        ('dwVersion', ULONG),
        ('dwHelpContext', ULONG),
        ('iid', IID),
        ('dwSourceSignature', ULONG),
        ('Source', ErrorInfoString),
        ('dwDescriptionSignature', ULONG),
        ('Description', ErrorInfoString),
        ('dwHelpFileSignature', ULONG),
        ('HelpFile', ErrorInfoString),
    )


# 2.2.21.5 EntryHeader
class EntryHeader(NDRSTRUCT):
    structure = (
        ('Signature', ULONG),
        ('cbEHBuffer', ULONG),
        ('cbSize', ULONG),
        ('reserved', ULONG),
        ('policyID', GUID),
    )


class EntryHeader_ARRAY(NDRUniConformantArray):
    item = EntryHeader


# 2.2.21.4 Context ORPC Extension
class ORPC_CONTEXT(NDRSTRUCT):
    structure = (
        ('SignatureVersion', ULONG),
        ('Version', ULONG),
        ('cPolicies', ULONG),
        ('cbBuffer', ULONG),
        ('cbSize', ULONG),
        ('hr', ULONG),
        ('hrServer', ULONG),
        ('reserved', ULONG),
        ('EntryHeader', EntryHeader_ARRAY),
        ('PolicyData', ':'),
    )

    def __init__(self, data=None, isNDR64=False):
        NDRSTRUCT.__init__(self, data, isNDR64)
        if data is None:
            self['SignatureVersion'] = 0x414E554B


# 2.2.22.1 CustomHeader
class CLSID_ARRAY(NDRUniConformantArray):
    item = CLSID


class PCLSID_ARRAY(NDRPOINTER):
    referent = (
        ('Data', CLSID_ARRAY),
    )


class DWORD_ARRAY(NDRUniConformantArray):
    item = DWORD


class PDWORD_ARRAY(NDRPOINTER):
    referent = (
        ('Data', DWORD_ARRAY),
    )


class CustomHeader(TypeSerialization1):
    structure = (
        ('totalSize', DWORD),
        ('headerSize', DWORD),
        ('dwReserved', DWORD),
        ('destCtx', DWORD),
        ('cIfs', DWORD),
        ('classInfoClsid', CLSID),
        ('pclsid', PCLSID_ARRAY),
        ('pSizes', PDWORD_ARRAY),
        ('pdwReserved', LPLONG),
    )

    def getData(self, soFar=0):
        self['headerSize'] = len(TypeSerialization1.getData(self, soFar)) + len(
            TypeSerialization1.getDataReferents(self, soFar))
        self['cIfs'] = len(self['pclsid'])
        return TypeSerialization1.getData(self, soFar)


# 2.2.22 Activation Properties BLOB
class ACTIVATION_BLOB(NDRTLSTRUCT):
    structure = (
        ('dwSize', ULONG),
        ('dwReserved', ULONG),
        ('CustomHeader', CustomHeader),
        ('Property', UNKNOWNDATA),
    )

    def getData(self, soFar=0):
        self['dwSize'] = len(self['CustomHeader'].getData(soFar)) + len(
            self['CustomHeader'].getDataReferents(soFar)) + len(self['Property'])
        self['CustomHeader']['totalSize'] = self['dwSize']
        return NDRTLSTRUCT.getData(self)


# 2.2.22.2.1 InstantiationInfoData
class IID_ARRAY(NDRUniConformantArray):
    item = IID


class PIID_ARRAY(NDRPOINTER):
    referent = (
        ('Data', IID_ARRAY),
    )


class InstantiationInfoData(TypeSerialization1):
    structure = (
        ('classId', CLSID),
        ('classCtx', DWORD),
        ('actvflags', DWORD),
        ('fIsSurrogate', LONG),
        ('cIID', DWORD),
        ('instFlag', DWORD),
        ('pIID', PIID_ARRAY),
        ('thisSize', DWORD),
        ('clientCOMVersion', COMVERSION),
    )


# 2.2.22.2.2 SpecialPropertiesData
class SpecialPropertiesData(TypeSerialization1):
    structure = (
        ('dwSessionId', ULONG),
        ('fRemoteThisSessionId', LONG),
        ('fClientImpersonating', LONG),
        ('fPartitionIDPresent', LONG),
        ('dwDefaultAuthnLvl', DWORD),
        ('guidPartition', GUID),
        ('dwPRTFlags', DWORD),
        ('dwOrigClsctx', DWORD),
        ('dwFlags', DWORD),
        ('Reserved0', DWORD),
        ('Reserved0_2', DWORD),
        ('Reserved', '32s=""'),
    )


# 2.2.22.2.3 InstanceInfoData
class InstanceInfoData(TypeSerialization1):
    structure = (
        ('fileName', LPWSTR),
        ('mode', DWORD),
        ('ifdROT', PMInterfacePointer),
        ('ifdStg', PMInterfacePointer),
    )


# 2.2.22.2.4.1 customREMOTE_REQUEST_SCM_INFO
class customREMOTE_REQUEST_SCM_INFO(NDRSTRUCT):
    structure = (
        ('ClientImpLevel', DWORD),
        ('cRequestedProtseqs', USHORT),
        ('pRequestedProtseqs', PUSHORT_ARRAY),
    )


class PcustomREMOTE_REQUEST_SCM_INFO(NDRPOINTER):
    referent = (
        ('Data', customREMOTE_REQUEST_SCM_INFO),
    )


# 2.2.22.2.4 ScmRequestInfoData
class ScmRequestInfoData(TypeSerialization1):
    structure = (
        ('pdwReserved', LPLONG),
        ('remoteRequest', PcustomREMOTE_REQUEST_SCM_INFO),
    )


# 2.2.22.2.5 ActivationContextInfoData
class ActivationContextInfoData(TypeSerialization1):
    structure = (
        ('clientOK', LONG),
        ('bReserved1', LONG),
        ('dwReserved1', DWORD),
        ('dwReserved2', DWORD),
        ('pIFDClientCtx', PMInterfacePointer),
        ('pIFDPrototypeCtx', PMInterfacePointer),
    )


# 2.2.22.2.6 LocationInfoData
class LocationInfoData(TypeSerialization1):
    structure = (
        ('machineName', LPWSTR),
        ('processId', DWORD),
        ('apartmentId', DWORD),
        ('contextId', DWORD),
    )


# 2.2.22.2.7.1 COSERVERINFO
class COSERVERINFO(NDRSTRUCT):
    structure = (
        ('dwReserved1', DWORD),
        ('pwszName', LPWSTR),
        ('pdwReserved', LPLONG),
        ('dwReserved2', DWORD),
    )


class PCOSERVERINFO(NDRPOINTER):
    referent = (
        ('Data', COSERVERINFO),
    )


# 2.2.22.2.7 SecurityInfoData
class SecurityInfoData(TypeSerialization1):
    structure = (
        ('dwAuthnFlags', DWORD),
        ('pServerInfo', PCOSERVERINFO),
        ('pdwReserved', LPLONG),
    )


# 2.2.22.2.8.1 customREMOTE_REPLY_SCM_INFO
class customREMOTE_REPLY_SCM_INFO(NDRSTRUCT):
    structure = (
        ('Oxid', OXID),
        ('pdsaOxidBindings', PDUALSTRINGARRAY),
        ('ipidRemUnknown', IPID),
        ('authnHint', DWORD),
        ('serverVersion', COMVERSION),
    )


class PcustomREMOTE_REPLY_SCM_INFO(NDRPOINTER):
    referent = (
        ('Data', customREMOTE_REPLY_SCM_INFO),
    )


# 2.2.22.2.8 ScmReplyInfoData
class ScmReplyInfoData(TypeSerialization1):
    structure = (
        ('pdwReserved', DWORD),
        ('remoteReply', PcustomREMOTE_REPLY_SCM_INFO),
    )


# 2.2.22.2.9 PropsOutInfo
class HRESULT_ARRAY(NDRUniConformantArray):
    item = HRESULT


class PHRESULT_ARRAY(NDRPOINTER):
    referent = (
        ('Data', HRESULT_ARRAY),
    )


class MInterfacePointer_ARRAY(NDRUniConformantArray):
    item = MInterfacePointer


class PMInterfacePointer_ARRAY(NDRUniConformantArray):
    item = PMInterfacePointer


class PPMInterfacePointer_ARRAY(NDRPOINTER):
    referent = (
        ('Data', PMInterfacePointer_ARRAY),
    )


class PropsOutInfo(TypeSerialization1):
    structure = (
        ('cIfs', DWORD),
        ('piid', PIID_ARRAY),
        ('phresults', PHRESULT_ARRAY),
        ('ppIntfData', PPMInterfacePointer_ARRAY),
    )


# 2.2.23 REMINTERFACEREF
class REMINTERFACEREF(NDRSTRUCT):
    structure = (
        ('ipid', IPID),
        ('cPublicRefs', LONG),
        ('cPrivateRefs', LONG),
    )


class REMINTERFACEREF_ARRAY(NDRUniConformantArray):
    item = REMINTERFACEREF


# 2.2.24 REMQIRESULT
class REMQIRESULT(NDRSTRUCT):
    structure = (
        ('hResult', HRESULT),
        ('std', STDOBJREF),
    )


# 2.2.25 PREMQIRESULT
class PREMQIRESULT(NDRPOINTER):
    referent = (
        ('Data', REMQIRESULT),
    )


# 2.2.26 REFIPID
REFIPID = GUID


################################################################################
# RPC CALLS
################################################################################

class DCOMCALL(NDRCALL):
    """Base class for DCOM calls - includes ORPCTHIS header"""
    commonHdr = (
        ('ORPCthis', ORPCTHIS),
    )


class DCOMANSWER(NDRCALL):
    """Base class for DCOM responses - includes ORPCTHAT header"""
    commonHdr = (
        ('ORPCthat', ORPCTHAT),
    )


# 3.1.2.5.1.1 IObjectExporter::ResolveOxid (Opnum 0)
class ResolveOxid(NDRCALL):
    opnum = 0
    structure = (
        ('pOxid', OXID),
        ('cRequestedProtseqs', USHORT),
        ('arRequestedProtseqs', USHORT_ARRAY),
    )


class ResolveOxidResponse(NDRCALL):
    structure = (
        ('ppdsaOxidBindings', PDUALSTRINGARRAY),
        ('pipidRemUnknown', IPID),
        ('pAuthnHint', DWORD),
        ('ErrorCode', error_status_t),
    )


# 3.1.2.5.1.2 IObjectExporter::SimplePing (Opnum 1)
class SimplePing(NDRCALL):
    opnum = 1
    structure = (
        ('pSetId', SETID),
    )


class SimplePingResponse(NDRCALL):
    structure = (
        ('ErrorCode', error_status_t),
    )


# 3.1.2.5.1.3 IObjectExporter::ComplexPing (Opnum 2)
class ComplexPing(NDRCALL):
    opnum = 2
    structure = (
        ('pSetId', SETID),
        ('SequenceNum', USHORT),
        ('cAddToSet', USHORT),
        ('cDelFromSet', USHORT),
        ('AddToSet', POID_ARRAY),
        ('DelFromSet', POID_ARRAY),
    )


class ComplexPingResponse(NDRCALL):
    structure = (
        ('pSetId', SETID),
        ('pPingBackoffFactor', USHORT),
        ('ErrorCode', error_status_t),
    )


# 3.1.2.5.1.4 IObjectExporter::ServerAlive (Opnum 3)
class ServerAlive(NDRCALL):
    opnum = 3
    structure = ()


class ServerAliveResponse(NDRCALL):
    structure = (
        ('ErrorCode', error_status_t),
    )


# 3.1.2.5.1.5 IObjectExporter::ResolveOxid2 (Opnum 4)
class ResolveOxid2(NDRCALL):
    opnum = 4
    structure = (
        ('pOxid', OXID),
        ('cRequestedProtseqs', USHORT),
        ('arRequestedProtseqs', USHORT_ARRAY),
    )


class ResolveOxid2Response(NDRCALL):
    structure = (
        ('ppdsaOxidBindings', PDUALSTRINGARRAY),
        ('pipidRemUnknown', IPID),
        ('pAuthnHint', DWORD),
        ('pComVersion', COMVERSION),
        ('ErrorCode', error_status_t),
    )


# 3.1.2.5.1.6 IObjectExporter::ServerAlive2 (Opnum 5)
class ServerAlive2(NDRCALL):
    opnum = 5
    structure = ()


class ServerAlive2Response(NDRCALL):
    structure = (
        ('pComVersion', COMVERSION),
        ('ppdsaOrBindings', PDUALSTRINGARRAY),
        ('pReserved', LPLONG),
        ('ErrorCode', error_status_t),
    )


# 3.1.2.5.2.3.1 IActivation::RemoteActivation (Opnum 0)
class RemoteActivation(NDRCALL):
    opnum = 0
    structure = (
        ('ORPCthis', ORPCTHIS),
        ('Clsid', GUID),
        ('pwszObjectName', LPWSTR),
        ('pObjectStorage', PMInterfacePointer),
        ('ClientImpLevel', DWORD),
        ('Mode', DWORD),
        ('Interfaces', DWORD),
        ('pIIDs', PIID_ARRAY),
        ('cRequestedProtseqs', USHORT),
        ('aRequestedProtseqs', USHORT_ARRAY),
    )


class RemoteActivationResponse(NDRCALL):
    structure = (
        ('ORPCthat', ORPCTHAT),
        ('pOxid', OXID),
        ('ppdsaOxidBindings', PDUALSTRINGARRAY),
        ('pipidRemUnknown', IPID),
        ('pAuthnHint', DWORD),
        ('pServerVersion', COMVERSION),
        ('phr', HRESULT),
        ('ppInterfaceData', PMInterfacePointer_ARRAY),
        ('pResults', HRESULT_ARRAY),
        ('ErrorCode', error_status_t),
    )


# 3.1.2.5.2.3.2 IRemoteSCMActivator::RemoteGetClassObject (Opnum 3)
class RemoteGetClassObject(NDRCALL):
    opnum = 3
    structure = (
        ('ORPCthis', ORPCTHIS),
        ('pActProperties', PMInterfacePointer),
    )


class RemoteGetClassObjectResponse(NDRCALL):
    structure = (
        ('ORPCthat', ORPCTHAT),
        ('ppActProperties', PMInterfacePointer),
        ('ErrorCode', error_status_t),
    )


# 3.1.2.5.2.3.3 IRemoteSCMActivator::RemoteCreateInstance (Opnum 4)
class RemoteCreateInstance(NDRCALL):
    opnum = 4
    structure = (
        ('ORPCthis', ORPCTHIS),
        ('pUnkOuter', PMInterfacePointer),
        ('pActProperties', PMInterfacePointer),
    )


class RemoteCreateInstanceResponse(NDRCALL):
    structure = (
        ('ORPCthat', ORPCTHAT),
        ('ppActProperties', PMInterfacePointer),
        ('ErrorCode', error_status_t),
    )


# 3.1.1.5.6.1.1 IRemUnknown::RemQueryInterface (Opnum 3)
class RemQueryInterface(DCOMCALL):
    opnum = 3
    structure = (
        ('ripid', REFIPID),
        ('cRefs', ULONG),
        ('cIids', USHORT),
        ('iids', IID_ARRAY),
    )


class RemQueryInterfaceResponse(DCOMANSWER):
    structure = (
        ('ppQIResults', PREMQIRESULT),
        ('ErrorCode', error_status_t),
    )


# 3.1.1.5.6.1.2 IRemUnknown::RemAddRef (Opnum 4)
class RemAddRef(DCOMCALL):
    opnum = 4
    structure = (
        ('cInterfaceRefs', USHORT),
        ('InterfaceRefs', REMINTERFACEREF_ARRAY),
    )


class RemAddRefResponse(DCOMANSWER):
    structure = (
        ('pResults', DWORD_ARRAY),
        ('ErrorCode', error_status_t),
    )


# 3.1.1.5.6.1.3 IRemUnknown::RemRelease (Opnum 5)
class RemRelease(DCOMCALL):
    opnum = 5
    structure = (
        ('cInterfaceRefs', USHORT),
        ('InterfaceRefs', REMINTERFACEREF_ARRAY),
    )


class RemReleaseResponse(DCOMANSWER):
    structure = (
        ('ErrorCode', error_status_t),
    )


################################################################################
# HELPER FUNCTIONS
################################################################################

def parse_string_bindings(data, security_offset):
    """Parse DUALSTRINGARRAY into list of STRINGBINDING objects"""
    str_bindings = data[:security_offset * 2]
    string_bindings = []
    
    while len(str_bindings) >= 4:
        if str_bindings[0:2] == b'\x00\x00':
            break
        binding = STRINGBINDING(str_bindings)
        string_bindings.append(binding)
        str_bindings = str_bindings[len(binding):]
    
    return string_bindings


def parse_security_bindings(data, security_offset):
    """Parse security bindings from DUALSTRINGARRAY"""
    sec_bindings = data[security_offset * 2:]
    security_bindings = []
    
    while len(sec_bindings) >= 4:
        if sec_bindings[0:2] == b'\x00\x00':
            break
        binding = SECURITYBINDING(sec_bindings)
        security_bindings.append(binding)
        sec_bindings = sec_bindings[len(binding):]
    
    return security_bindings
