# OLE Automation Types for aiosmb DCOM
#
# Based on [MS-OAUT] specification and impacket's implementation
# Provides BSTR, VARIANT, IDispatch and other OLE Automation types
#

from struct import pack, unpack
import random

from aiosmb.dcerpc.v5.ndr import (
    NDRSTRUCT, NDRPOINTER, NDRUniConformantArray,
    NDRUNION, NDRENUM, NDR, NDRUniConformantVaryingArray,
)
from aiosmb.dcerpc.v5.dtypes import (
    ULONG, DWORD, USHORT, LONG, LPWSTR, WSTR, GUID, UINT, SHORT, BYTE,
    LONGLONG, ULONGLONG, FLOAT, DOUBLE, HRESULT, CHAR, INT,
    PSHORT, PLONG, PLONGLONG, PFLOAT, PDOUBLE, PHRESULT, PCHAR,
    PUSHORT, PULONG, PULONGLONG, PINT, PUINT, NULL,
)
from aiosmb.dcerpc.v5.dcom.dcomrt import (
    DCOMCALL, DCOMANSWER, PMInterfacePointer,
    MInterfacePointer, MInterfacePointer_ARRAY,
    BYTE_ARRAY, PPMInterfacePointer, ORPCTHIS, ORPCTHAT,
)
from aiosmb.dcerpc.v5.dcom.interface import INTERFACE
from aiosmb.dcerpc.v5.dcom.remunknown import IRemUnknown2
from aiosmb.dcerpc.v5.uuid import string_to_bin

################################################################################
# CONSTANTS (MS-OAUT 1.9)
################################################################################

IID_IDispatch = string_to_bin('00020400-0000-0000-C000-000000000046')
IID_ITypeInfo = string_to_bin('00020401-0000-0000-C000-000000000046')
IID_ITypeComp = string_to_bin('00020403-0000-0000-C000-000000000046')
IID_NULL = string_to_bin('00000000-0000-0000-0000-000000000000')

error_status_t = ULONG
LCID = DWORD
WORD = USHORT

# 2.2.2 IID
IID = GUID

# 2.2.3 LPOLESTR
LPOLESTR = LPWSTR
OLESTR = WSTR

# 2.2.4 REFIID
REFIID = IID

# 2.2.25 DATE
DATE = DOUBLE

class PDATE(NDRPOINTER):
    referent = (
        ('Data', DATE),
    )

# 2.2.27 VARIANT_BOOL
VARIANT_BOOL = USHORT

class PVARIANT_BOOL(NDRPOINTER):
    referent = (
        ('Data', VARIANT_BOOL),
    )

# 3.1.4.4 IDispatch::Invoke dwFlags
DISPATCH_METHOD = 0x00000001
DISPATCH_PROPERTYGET = 0x00000002
DISPATCH_PROPERTYPUT = 0x00000004
DISPATCH_PROPERTYPUTREF = 0x00000008
DISPATCH_zeroVarResult = 0x00020000
DISPATCH_zeroExcepInfo = 0x00040000
DISPATCH_zeroArgErr = 0x00080000

################################################################################
# BSTR - Basic String (MS-OAUT 2.2.23)
################################################################################

# 2.2.23.1 FLAGGED_WORD_BLOB
class USHORT_ARRAY(NDRUniConformantArray):
    """Array of unsigned shorts (UTF-16LE code units)"""
    item = '<H'


class FLAGGED_WORD_BLOB(NDRSTRUCT):
    """
    FLAGGED_WORD_BLOB structure for BSTR.
    
    From MS-OAUT 2.2.23.1:
    typedef struct tagFLAGGED_WORD_BLOB {
        unsigned long cBytes;
        unsigned long clSize;
        [size_is(clSize)] unsigned short asData[];
    } FLAGGED_WORD_BLOB;
    """
    structure = (
        ('cBytes', ULONG),
        ('clSize', ULONG),
        ('asData', USHORT_ARRAY),
    )
    
    def __setitem__(self, key, value):
        if key == 'asData':
            # Convert string to array of UTF-16LE code units
            array = []
            for letter in value:
                encoded = letter.encode('utf-16le')
                array.append(unpack('<H', encoded)[0])
            self.fields[key]['Data'] = array
            self['cBytes'] = len(value) * 2
            self['clSize'] = len(value)
            self.data = None  # Force recompute
        else:
            return NDRSTRUCT.__setitem__(self, key, value)
    
    def __getitem__(self, key):
        if key == 'asData':
            value = ''
            for letter in self.fields['asData']['Data']:
                value += pack('<H', letter).decode('utf-16le')
            return value
        else:
            return NDRSTRUCT.__getitem__(self, key)


# 2.2.23.2 BSTR Type Definition
class BSTR(NDRPOINTER):
    """
    BSTR (Basic String) type from OLE Automation.
    
    A pointer to FLAGGED_WORD_BLOB containing a length-prefixed Unicode string.
    """
    referent = (
        ('Data', FLAGGED_WORD_BLOB),
    )


class PBSTR(NDRPOINTER):
    """Pointer to BSTR"""
    referent = (
        ('Data', BSTR),
    )


class LPBSTR(NDRPOINTER):
    """Long pointer to BSTR"""
    referent = (
        ('Data', BSTR),
    )


################################################################################
# 2.2.7 VARIANT Type Constants
################################################################################

class VARENUM(NDRENUM):
    class enumItems:
        VT_EMPTY = 0
        VT_NULL = 1
        VT_I2 = 2
        VT_I4 = 3
        VT_R4 = 4
        VT_R8 = 5
        VT_CY = 6
        VT_DATE = 7
        VT_BSTR = 8
        VT_DISPATCH = 9
        VT_ERROR = 0xa
        VT_BOOL = 0xb
        VT_VARIANT = 0xc
        VT_UNKNOWN = 0xd
        VT_DECIMAL = 0xe
        VT_I1 = 0x10
        VT_UI1 = 0x11
        VT_UI2 = 0x12
        VT_UI4 = 0x13
        VT_I8 = 0x14
        VT_UI8 = 0x15
        VT_INT = 0x16
        VT_UINT = 0x17
        VT_VOID = 0x18
        VT_HRESULT = 0x19
        VT_PTR = 0x1a
        VT_SAFEARRAY = 0x1b
        VT_CARRAY = 0x1c
        VT_USERDEFINED = 0x1d
        VT_LPSTR = 0x1e
        VT_LPWSTR = 0x1f
        VT_RECORD = 0x24
        VT_INT_PTR = 0x25
        VT_UINT_PTR = 0x26
        VT_ARRAY = 0x2000
        VT_BYREF = 0x4000


# 2.2.24 CURRENCY
class CURRENCY(NDRSTRUCT):
    structure = (
        ('int64', LONGLONG),
    )

class PCURRENCY(NDRPOINTER):
    referent = (
        ('Data', CURRENCY),
    )


# 2.2.26 DECIMAL
class DECIMAL(NDRSTRUCT):
    structure = (
        ('wReserved', WORD),
        ('scale', BYTE),
        ('sign', BYTE),
        ('Hi32', ULONG),
        ('Lo64', ULONGLONG),
    )

class PDECIMAL(NDRPOINTER):
    referent = (
        ('Data', DECIMAL),
    )


# 2.2.28.2 BRECORD
class _wireBRECORD(NDRSTRUCT):
    structure = (
        ('fFlags', LONGLONG),
        ('clSize', LONGLONG),
        ('pRecInfo', MInterfacePointer),
        ('pRecord', BYTE_ARRAY),
    )

class BRECORD(NDRPOINTER):
    referent = (
        ('Data', _wireBRECORD),
    )


# 2.2.29 VARIANT - Forward declaration placeholder
class EMPTY(NDR):
    align = 0
    structure = ()


class varUnion(NDRUNION):
    commonHdr = (
        ('tag', ULONG),
    )
    union = {
        VARENUM.enumItems.VT_I8: ('llVal', LONGLONG),
        VARENUM.enumItems.VT_I4: ('lVal', LONG),
        VARENUM.enumItems.VT_UI1: ('bVal', BYTE),
        VARENUM.enumItems.VT_I2: ('iVal', SHORT),
        VARENUM.enumItems.VT_R4: ('fltVal', FLOAT),
        VARENUM.enumItems.VT_R8: ('dblVal', DOUBLE),
        VARENUM.enumItems.VT_BOOL: ('boolVal', VARIANT_BOOL),
        VARENUM.enumItems.VT_ERROR: ('scode', HRESULT),
        VARENUM.enumItems.VT_CY: ('cyVal', CURRENCY),
        VARENUM.enumItems.VT_DATE: ('date', DATE),
        VARENUM.enumItems.VT_BSTR: ('bstrVal', BSTR),
        VARENUM.enumItems.VT_UNKNOWN: ('punkVal', PMInterfacePointer),
        VARENUM.enumItems.VT_DISPATCH: ('pdispVal', PMInterfacePointer),
        VARENUM.enumItems.VT_RECORD: ('brecVal', BRECORD),
        VARENUM.enumItems.VT_I1: ('cVal', CHAR),
        VARENUM.enumItems.VT_UI2: ('uiVal', USHORT),
        VARENUM.enumItems.VT_UI4: ('ulVal', ULONG),
        VARENUM.enumItems.VT_UI8: ('ullVal', ULONGLONG),
        VARENUM.enumItems.VT_INT: ('intVal', INT),
        VARENUM.enumItems.VT_UINT: ('uintVal', UINT),
        VARENUM.enumItems.VT_DECIMAL: ('decVal', DECIMAL),
        VARENUM.enumItems.VT_EMPTY: ('empty', EMPTY),
        VARENUM.enumItems.VT_NULL: ('null', EMPTY),
    }


class wireVARIANTStr(NDRSTRUCT):
    structure = (
        ('clSize', DWORD),
        ('rpcReserved', DWORD),
        ('vt', USHORT),
        ('wReserved1', USHORT),
        ('wReserved2', USHORT),
        ('wReserved3', USHORT),
        ('_varUnion', varUnion),
    )
    
    def getAlignment(self):
        return 8


class VARIANT(NDRPOINTER):
    referent = (
        ('Data', wireVARIANTStr),
    )


class PVARIANT(NDRPOINTER):
    referent = (
        ('Data', VARIANT),
    )


################################################################################
# 2.2.32 DISPID and 2.2.33 DISPPARAMS
################################################################################

DISPID = LONG

class DISPID_ARRAY(NDRUniConformantArray):
    item = '<L'

class PDISPID_ARRAY(NDRPOINTER):
    referent = (
        ('Data', DISPID_ARRAY),
    )

class VARIANT_ARRAY(NDRUniConformantArray):
    def __init__(self, data=None, isNDR64=False):
        NDRUniConformantArray.__init__(self, data, isNDR64)
        self.item = VARIANT

class PVARIANT_ARRAY(NDRPOINTER):
    referent = (
        ('Data', VARIANT_ARRAY),
    )

class DISPPARAMS(NDRSTRUCT):
    structure = (
        ('rgvarg', PVARIANT_ARRAY),
        ('rgdispidNamedArgs', PDISPID_ARRAY),
        ('cArgs', UINT),
        ('cNamedArgs', UINT),
    )


# 2.2.34 EXCEPINFO
class EXCEPINFO(NDRSTRUCT):
    structure = (
        ('wCode', WORD),
        ('wReserved', WORD),
        ('bstrSource', BSTR),
        ('bstrDescription', BSTR),
        ('bstrHelpFile', BSTR),
        ('dwHelpContext', DWORD),
        ('pvReserved', ULONG),
        ('pfnDeferredFillIn', ULONG),
        ('scode', HRESULT),
    )


# Arrays for IDispatch
class OLESTR_ARRAY(NDRUniConformantArray):
    item = LPOLESTR

class UINT_ARRAY(NDRUniConformantArray):
    item = '<L'


################################################################################
# IDispatch RPC Calls (MS-OAUT 3.1.4)
################################################################################

# 3.1.4.1 IDispatch::GetTypeInfoCount (Opnum 3)
class IDispatch_GetTypeInfoCount(DCOMCALL):
    opnum = 3
    structure = (
        ('pwszMachineName', LPWSTR),
    )

class IDispatch_GetTypeInfoCountResponse(DCOMANSWER):
    structure = (
        ('pctinfo', ULONG),
        ('ErrorCode', error_status_t),
    )


# 3.1.4.2 IDispatch::GetTypeInfo (Opnum 4)
class IDispatch_GetTypeInfo(DCOMCALL):
    opnum = 4
    structure = (
        ('iTInfo', ULONG),
        ('lcid', DWORD),
    )

class IDispatch_GetTypeInfoResponse(DCOMANSWER):
    structure = (
        ('ppTInfo', PMInterfacePointer),
        ('ErrorCode', error_status_t),
    )


# 3.1.4.3 IDispatch::GetIDsOfNames (Opnum 5)
class IDispatch_GetIDsOfNames(DCOMCALL):
    opnum = 5
    structure = (
        ('riid', REFIID),
        ('rgszNames', OLESTR_ARRAY),
        ('cNames', UINT),
        ('lcid', LCID),
    )

class IDispatch_GetIDsOfNamesResponse(DCOMANSWER):
    structure = (
        ('rgDispId', DISPID_ARRAY),
        ('ErrorCode', error_status_t),
    )


# 3.1.4.4 IDispatch::Invoke (Opnum 6)
class IDispatch_Invoke(DCOMCALL):
    opnum = 6
    structure = (
        ('dispIdMember', DISPID),
        ('riid', REFIID),
        ('lcid', LCID),
        ('dwFlags', DWORD),
        ('pDispParams', DISPPARAMS),
        ('cVarRef', UINT),
        ('rgVarRefIdx', UINT_ARRAY),
        ('rgVarRef', VARIANT_ARRAY),
    )

class IDispatch_InvokeResponse(DCOMANSWER):
    structure = (
        ('pVarResult', VARIANT),
        ('pExcepInfo', EXCEPINFO),
        ('pArgErr', UINT),
        ('ErrorCode', error_status_t),
    )


################################################################################
# Helper Functions
################################################################################

def checkNullString(string):
    """Ensure string is null-terminated"""
    if string == NULL:
        return string
    if string[-1:] != '\x00':
        return string + '\x00'
    return string


################################################################################
# IDispatch Interface Wrapper
################################################################################

class IDispatch(IRemUnknown2):
    """
    IDispatch interface for OLE Automation.
    
    Provides methods for late-bound invocation of COM object methods/properties.
    """
    
    def __init__(self, interface):
        IRemUnknown2.__init__(self, interface)
        self._iid = IID_IDispatch
    
    async def GetTypeInfoCount(self):
        """Get the number of type information interfaces"""
        request = IDispatch_GetTypeInfoCount()
        resp, err = await self.request(request, iid=self._iid, uuid=self.get_iPid())
        return resp, err
    
    async def GetTypeInfo(self, iTInfo=0, lcid=0):
        """Get type information interface"""
        request = IDispatch_GetTypeInfo()
        request['iTInfo'] = iTInfo
        request['lcid'] = lcid
        resp, err = await self.request(request, iid=self._iid, uuid=self.get_iPid())
        if err is not None:
            return None, err
        # Return ITypeInfo interface
        return INTERFACE(
            self.get_cinstance(),
            b''.join(resp['ppTInfo']['abData']),
            self.get_ipidRemUnknown(),
            target=self.get_target()
        ), None
    
    async def GetIDsOfNames(self, rgszNames, lcid=0):
        """
        Get dispatch IDs for a set of names.
        
        Args:
            rgszNames: List of names to look up
            lcid: Locale ID
        
        Returns:
            List of DISPIDs for the names
        """
        request = IDispatch_GetIDsOfNames()
        request['riid'] = IID_NULL
        for name in rgszNames:
            tmpName = LPOLESTR()
            tmpName['Data'] = checkNullString(name)
            request['rgszNames'].append(tmpName)
        request['cNames'] = len(rgszNames)
        request['lcid'] = lcid
        
        resp, err = await self.request(request, iid=self._iid, uuid=self.get_iPid())
        if err is not None:
            return None, err
        
        IDs = list(resp['rgDispId'])
        return IDs, None
    
    async def Invoke(self, dispIdMember, lcid=0, dwFlags=DISPATCH_METHOD,
                     pDispParams=None, cVarRef=0, rgVarRefIdx=None, rgVarRef=None):
        """
        Invoke a method or access a property.
        
        Args:
            dispIdMember: DISPID of method/property
            lcid: Locale ID
            dwFlags: Invocation flags (DISPATCH_METHOD, DISPATCH_PROPERTYGET, etc.)
            pDispParams: Parameters for the call
            cVarRef: Count of by-reference parameters
            rgVarRefIdx: Indices of by-ref parameters
            rgVarRef: By-ref parameter values
        
        Returns:
            Response with result and exception info
        """
        request = IDispatch_Invoke()
        request['dispIdMember'] = dispIdMember
        request['riid'] = IID_NULL
        request['lcid'] = lcid
        request['dwFlags'] = dwFlags
        
        if pDispParams is None:
            pDispParams = DISPPARAMS()
            pDispParams['cArgs'] = 0
            pDispParams['cNamedArgs'] = 0
        request['pDispParams'] = pDispParams
        
        request['cVarRef'] = cVarRef
        if rgVarRefIdx is None:
            rgVarRefIdx = []
        request['rgVarRefIdx'] = rgVarRefIdx
        if rgVarRef is None:
            rgVarRef = []
        request['rgVarRef'] = rgVarRef
        
        resp, err = await self.request(request, iid=self._iid, uuid=self.get_iPid())
        return resp, err
    
    async def pakIdOfName(self, name):
        """Helper: Get DISPID for a single name"""
        ids, err = await self.GetIDsOfNames([name])
        if err is not None:
            return None, err
        if not ids:
            return None, Exception(f"Name '{name}' not found")
        return ids[0], None
    
    async def pakGet(self, dispId):
        """Helper: Get a property by DISPID"""
        resp, err = await self.Invoke(dispId, dwFlags=DISPATCH_PROPERTYGET)
        if err is not None:
            return None, err
        
        # Extract the result - it's wireVARIANTStr directly
        result = resp['pVarResult']
        vt = result['vt']
        
        # If it's a dispatch interface, return the interface
        if vt == VARENUM.enumItems.VT_DISPATCH:
            return INTERFACE(
                self.get_cinstance(),
                b''.join(result['_varUnion']['pdispVal']['abData']),
                self.get_ipidRemUnknown(),
                target=self.get_target()
            ), None
        
        return result, None
    
    async def pakInvoke(self, dispId, *args):
        """
        Helper: Invoke a method by DISPID with arguments.
        
        Args are converted to VARIANT and passed in reverse order (per OLE convention).
        """
        # Build DISPPARAMS
        pDispParams = DISPPARAMS()
        pDispParams['cArgs'] = len(args)
        pDispParams['cNamedArgs'] = 0
        
        # Arguments are passed in reverse order
        for arg in reversed(args):
            variant = VARIANT()
            varData = wireVARIANTStr()
            varData['clSize'] = 0x18  # Standard size
            varData['rpcReserved'] = 0
            
            if isinstance(arg, str):
                varData['vt'] = VARENUM.enumItems.VT_BSTR
                # Set the union tag first
                varData['_varUnion']['tag'] = VARENUM.enumItems.VT_BSTR
                bstr = BSTR()
                bstr['Data']['asData'] = arg
                varData['_varUnion']['bstrVal'] = bstr
            elif isinstance(arg, int):
                varData['vt'] = VARENUM.enumItems.VT_I4
                varData['_varUnion']['tag'] = VARENUM.enumItems.VT_I4
                varData['_varUnion']['lVal'] = arg
            elif isinstance(arg, bool):
                varData['vt'] = VARENUM.enumItems.VT_BOOL
                varData['_varUnion']['tag'] = VARENUM.enumItems.VT_BOOL
                varData['_varUnion']['boolVal'] = 0xFFFF if arg else 0
            else:
                # Default to string
                varData['vt'] = VARENUM.enumItems.VT_BSTR
                varData['_varUnion']['tag'] = VARENUM.enumItems.VT_BSTR
                bstr = BSTR()
                bstr['Data']['asData'] = str(arg)
                varData['_varUnion']['bstrVal'] = bstr
            
            variant['Data'] = varData
            pDispParams['rgvarg'].append(variant)
        
        resp, err = await self.Invoke(dispId, dwFlags=DISPATCH_METHOD, pDispParams=pDispParams)
        return resp, err
