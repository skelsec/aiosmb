#!/usr/bin/env python3
"""
ICertAdminD2 DCOM Interface for AD CS Certificate Authority administration

This module implements the read-only subset of the ICertAdminD/ICertAdminD2
DCOM interfaces needed to inspect the configuration of an Active Directory
Certificate Services (AD CS) Certificate Authority.

Based on:
    - [MS-CSRA] Certificate Services Remote Administration Protocol
    - [MS-OAUT] OLE Automation Protocol (VARIANT/SAFEARRAY wire format)

CLSID: {D99E6E73-FC88-11D0-B498-00A0C90312F3} - CCertAdminD
IID:   {D99E6E71-FC88-11D0-B498-00A0C90312F3} - ICertAdminD
IID:   {7FE0D935-DDA6-443F-85D0-1CFB58FE41DD} - ICertAdminD2
"""

import enum
from struct import pack, unpack

from aiosmb import logger
from aiosmb.dcerpc.v5.dcom.remunknown import IRemUnknown
from aiosmb.dcerpc.v5.dcom.dcomrt import DCOMCALL, DCOMANSWER
from aiosmb.dcerpc.v5.icpr import CERTTRANSBLOB
from aiosmb.dcerpc.v5.dcom.oaut import VARENUM
from aiosmb.dcerpc.v5.rpcrt import DCERPCException, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from aiosmb.dcerpc.v5.dtypes import LPWSTR, WSTR, LONG, ULONG, DWORD
from aiosmb.dcerpc.v5.uuid import string_to_bin, uuidtup_to_bin
from aiosmb.dcerpc.v5 import hresult_errors, system_errors


# =========================================================================
# Constants and Protocol UUIDs
# =========================================================================

# CCertAdminD CLSID - for DCOM activation
CLSID_CCertAdminD = string_to_bin('D99E6E73-FC88-11D0-B498-00A0C90312F3')

# Interface IDs
IID_ICertAdminD = uuidtup_to_bin(('D99E6E71-FC88-11D0-B498-00A0C90312F3', '0.0'))
IID_ICertAdminD2 = uuidtup_to_bin(('7FE0D935-DDA6-443F-85D0-1CFB58FE41DD', '0.0'))

# Registry node holding the settings of the default policy module
# (MS-CSRA 3.1.1.10), relative to the CA's configuration key
POLICY_MODULE_NODE = 'PolicyModules\\CertificateAuthority_MicrosoftDefault.Policy'

# Property types for GetCAProperty (MS-CSRA 3.1.4.2.2)
PROPTYPE_LONG = 1
PROPTYPE_DATE = 2
PROPTYPE_BINARY = 3
PROPTYPE_STRING = 4

# Disposition values returned by ResubmitRequest (MS-WCCE 3.2.1.4.2.1)
CR_DISP_INCOMPLETE = 0
CR_DISP_ERROR = 1
CR_DISP_DENIED = 2
CR_DISP_ISSUED = 3
CR_DISP_ISSUED_OUT_OF_BAND = 4
CR_DISP_UNDER_SUBMISSION = 5
CR_DISP_REVOKED = 6

DISPOSITION_NAMES = {
    CR_DISP_INCOMPLETE: 'Incomplete',
    CR_DISP_ERROR: 'Error',
    CR_DISP_DENIED: 'Denied',
    CR_DISP_ISSUED: 'Issued',
    CR_DISP_ISSUED_OUT_OF_BAND: 'Issued out of band',
    CR_DISP_UNDER_SUBMISSION: 'Under submission',
    CR_DISP_REVOKED: 'Revoked',
}

# Property ids for GetCAProperty (MS-CSRA 3.1.4.2.2 / MS-WCCE 3.2.1.4.3.2)
CR_PROP_FILEVERSION = 0x01
CR_PROP_PRODUCTVERSION = 0x02
CR_PROP_EXITCOUNT = 0x03
CR_PROP_EXITDESCRIPTION = 0x04
CR_PROP_POLICYDESCRIPTION = 0x05
CR_PROP_CANAME = 0x06
CR_PROP_SANITIZEDCANAME = 0x07
CR_PROP_SHAREDFOLDER = 0x08
CR_PROP_PARENTCA = 0x09
CR_PROP_CATYPE = 0x0A
CR_PROP_CASIGCERTCOUNT = 0x0B
CR_PROP_CASIGCERT = 0x0C
CR_PROP_CASIGCERTCHAIN = 0x0D
CR_PROP_CAXCHGCERTCOUNT = 0x0E
CR_PROP_CAXCHGCERT = 0x0F
CR_PROP_CAXCHGCERTCHAIN = 0x10
CR_PROP_BASECRL = 0x11
CR_PROP_DELTACRL = 0x12
CR_PROP_CACERTSTATE = 0x13
CR_PROP_CRLSTATE = 0x14
CR_PROP_CAPROPIDMAX = 0x15
CR_PROP_DNSNAME = 0x16
CR_PROP_ROLESEPARATIONENABLED = 0x17
CR_PROP_KRACERTUSEDCOUNT = 0x18
CR_PROP_KRACERTCOUNT = 0x19
CR_PROP_KRACERT = 0x1A
CR_PROP_KRACERTSTATE = 0x1B
CR_PROP_ADVANCEDSERVER = 0x1C
CR_PROP_TEMPLATES = 0x1D
CR_PROP_BASECRLPUBLISHSTATUS = 0x1E
CR_PROP_DELTACRLPUBLISHSTATUS = 0x1F
CR_PROP_CASIGCERTCRLCHAIN = 0x20
CR_PROP_CAXCHGCERTCRLCHAIN = 0x21
CR_PROP_CACERTSTATUSCODE = 0x22
CR_PROP_CAFORWARDCROSSCERT = 0x23
CR_PROP_CABACKWARDCROSSCERT = 0x24
CR_PROP_CAFORWARDCROSSCERTSTATE = 0x25
CR_PROP_CABACKWARDCROSSCERTSTATE = 0x26
CR_PROP_CACERTVERSION = 0x27
CR_PROP_SANITIZEDCASHORTNAME = 0x28
CR_PROP_CERTCDPURLS = 0x29
CR_PROP_CERTAIAURLS = 0x2A
CR_PROP_CERTAIAOCSPURLS = 0x2B
CR_PROP_LOCALENAME = 0x2C
CR_PROP_SUBJECTTEMPLATE_OIDS = 0x2D

# The CA answers these PROPTYPE_LONG properties with a whole CAINFO structure
# (MS-WCCE 2.2.2.4) instead of a single value. Offsets of the properties in it.
CAINFO_OFFSETS = {
    CR_PROP_CATYPE: 4,
    CR_PROP_CASIGCERTCOUNT: 8,
    CR_PROP_CAXCHGCERTCOUNT: 12,
    CR_PROP_EXITCOUNT: 16,
    CR_PROP_CAPROPIDMAX: 20,
    CR_PROP_ROLESEPARATIONENABLED: 24,
    CR_PROP_KRACERTUSEDCOUNT: 28,
    CR_PROP_KRACERTCOUNT: 32,
    CR_PROP_ADVANCEDSERVER: 36,
}


class EditFlags(enum.IntFlag):
    """Policy module EditFlags (MS-CSRA 3.1.1.10 Config_CA_Policy_EditFlags)"""
    EDITF_ENABLEREQUESTEXTENSIONS = 0x00000001
    EDITF_REQUESTEXTENSIONLIST = 0x00000002
    EDITF_DISABLEEXTENSIONLIST = 0x00000004
    EDITF_ADDOLDKEYUSAGE = 0x00000008
    EDITF_ADDOLDCERTTYPE = 0x00000010
    EDITF_ATTRIBUTEENDDATE = 0x00000020
    EDITF_BASICCONSTRAINTSCRITICAL = 0x00000040
    EDITF_BASICCONSTRAINTSCA = 0x00000080
    EDITF_ENABLEAKIKEYID = 0x00000100
    EDITF_ATTRIBUTECA = 0x00000200
    EDITF_IGNOREREQUESTERGROUP = 0x00000400
    EDITF_ENABLEAKIISSUERNAME = 0x00000800
    EDITF_ENABLEAKIISSUERSERIAL = 0x00001000
    EDITF_ENABLEAKICRITICAL = 0x00002000
    EDITF_SERVERUPGRADED = 0x00004000
    EDITF_ATTRIBUTEEKU = 0x00008000
    EDITF_ENABLEDEFAULTSMIME = 0x00010000
    EDITF_EMAILOPTIONAL = 0x00020000
    EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000
    EDITF_ENABLELDAPREFERRALS = 0x00080000
    EDITF_ENABLECHASECLIENTDC = 0x00100000
    EDITF_AUDITCERTTEMPLATELOAD = 0x00200000
    EDITF_DISABLEOLDOSCNGUPDATE = 0x00400000
    EDITF_ENABLEOCSPREVNOCHECK = 0x00800000
    EDITF_ENABLERENEWONBEHALFOF = 0x01000000
    EDITF_ENABLEKEYENCIPHERMENTCACERT = 0x02000000


class InterfaceFlags(enum.IntFlag):
    """CA InterfaceFlags (MS-CSRA 3.1.1.10 Config_CA_Interface_Flags)"""
    IF_LOCKICERTREQUEST = 0x00000001
    IF_NOREMOTEICERTREQUEST = 0x00000002
    IF_NOLOCALICERTREQUEST = 0x00000004
    IF_NORPCICERTREQUEST = 0x00000008
    IF_NOREMOTEICERTADMIN = 0x00000010
    IF_NOLOCALICERTADMIN = 0x00000020
    IF_NOREMOTEICERTADMINBACKUP = 0x00000040
    IF_NOLOCALICERTADMINBACKUP = 0x00000080
    IF_NOSNAPSHOTBACKUP = 0x00000100
    IF_ENFORCEENCRYPTICERTREQUEST = 0x00000200
    IF_ENFORCEENCRYPTICERTADMIN = 0x00000400
    IF_ENABLEEXITKEYRETRIEVAL = 0x00000800
    IF_ENABLEADMINASAUDITOR = 0x00001000


class CAAccessMask(enum.IntFlag):
    """
    Access rights used in the CA security descriptor and returned by
    GetMyRoles (MS-CSRA 2.2.1.11 / 3.1.1.7)
    """
    CA_ACCESS_ADMIN = 0x00000001     # Manage CA
    CA_ACCESS_OFFICER = 0x00000002   # Issue and Manage Certificates
    CA_ACCESS_AUDITOR = 0x00000004
    CA_ACCESS_OPERATOR = 0x00000008
    CA_ACCESS_READ = 0x00000100
    CA_ACCESS_ENROLL = 0x00000200


class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__(self):
        if self.error_code in hresult_errors.ERROR_MESSAGES:
            error_msg_short = hresult_errors.ERROR_MESSAGES[self.error_code][0]
            error_msg_verbose = hresult_errors.ERROR_MESSAGES[self.error_code][1]
            return 'CertAdmin SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        if self.error_code & 0xFFFF0000 == 0x80070000 and self.error_code & 0xFFFF in system_errors.ERROR_MESSAGES:
            error_msg_short, error_msg_verbose = system_errors.ERROR_MESSAGES[self.error_code & 0xFFFF]
            return 'CertAdmin SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        return 'CertAdmin SessionError: unknown error code: 0x%x' % self.error_code


# =========================================================================
# Protocol Structures for MS-CSRA
# =========================================================================

# 3.1.4.1.8 ICertAdminD::Ping (Opnum 18)
class Ping(DCOMCALL):
    opnum = 18
    structure = (
        ('pwszAuthority', LPWSTR),
    )


class PingResponse(DCOMANSWER):
    structure = (
        ('ErrorCode', ULONG),
    )


# 3.1.4.1.3 ICertAdminD::ResubmitRequest (Opnum 5)
class ResubmitRequest(DCOMCALL):
    opnum = 5
    structure = (
        ('pwszAuthority', LPWSTR),
        ('dwRequestId', DWORD),
    )


class ResubmitRequestResponse(DCOMANSWER):
    structure = (
        ('pdwDisposition', DWORD),
        ('ErrorCode', ULONG),
    )


# 3.1.4.2.2 ICertAdminD2::GetCAProperty (Opnum 32)
class GetCAProperty(DCOMCALL):
    opnum = 32
    structure = (
        ('pwszAuthority', LPWSTR),
        ('PropId', LONG),
        ('PropIndex', LONG),
        ('PropType', LONG),
    )


class GetCAPropertyResponse(DCOMANSWER):
    structure = (
        ('pctbPropertyValue', CERTTRANSBLOB),
        ('ErrorCode', ULONG),
    )


# 3.1.4.2.6 ICertAdminD2::GetCASecurity (Opnum 36)
class GetCASecurity(DCOMCALL):
    opnum = 36
    structure = (
        ('pwszAuthority', LPWSTR),
    )


class GetCASecurityResponse(DCOMANSWER):
    structure = (
        ('pctbSD', CERTTRANSBLOB),
        ('ErrorCode', ULONG),
    )


# 3.1.4.2.14 ICertAdminD2::GetConfigEntry (Opnum 44)
class GetConfigEntry(DCOMCALL):
    opnum = 44
    structure = (
        ('pwszAuthority', LPWSTR),
        ('pwszNodePath', LPWSTR),
        ('pwszEntry', WSTR),
    )


class GetConfigEntryResponse(DCOMANSWER):
    # The VARIANT is kept as raw bytes (with the trailing ErrorCode) and
    # decoded by parse_variant(): REG_MULTI_SZ and REG_BINARY values come
    # back as SAFEARRAYs which the generic oaut.VARIANT union doesn't cover.
    structure = (
        ('pVariant', ':'),
    )


# 3.1.4.2.15 ICertAdminD2::SetConfigEntry (Opnum 45)
class SetConfigEntry(DCOMCALL):
    # The VARIANT is marshalled by hand (build_variant_i4) and carried as raw
    # bytes, the same way GetConfigEntry's response keeps it raw. It is the last
    # [in] parameter, so appending raw bytes doesn't disturb any field after it.
    opnum = 45
    structure = (
        ('pwszAuthority', LPWSTR),
        ('pwszNodePath', LPWSTR),
        ('pwszEntry', WSTR),
        ('pVariant', ':'),
    )


class SetConfigEntryResponse(DCOMANSWER):
    structure = (
        ('ErrorCode', ULONG),
    )


# 3.1.4.2.17 ICertAdminD2::GetMyRoles (Opnum 47)
class GetMyRoles(DCOMCALL):
    opnum = 47
    structure = (
        ('pwszAuthority', LPWSTR),
    )


class GetMyRolesResponse(DCOMANSWER):
    structure = (
        ('pdwRoles', LONG),
        ('ErrorCode', ULONG),
    )


# =========================================================================
# VARIANT wire format parser (MS-OAUT 2.2.29.1 / 2.2.30.10)
# =========================================================================

VT_ARRAY = VARENUM.enumItems.VT_ARRAY
VT_EMPTY = VARENUM.enumItems.VT_EMPTY
VT_NULL = VARENUM.enumItems.VT_NULL
VT_I4 = VARENUM.enumItems.VT_I4
VT_UI4 = VARENUM.enumItems.VT_UI4
VT_BSTR = VARENUM.enumItems.VT_BSTR
VT_UI1 = VARENUM.enumItems.VT_UI1


class _Reader:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def align(self, n):
        self.pos += (n - self.pos % n) % n

    def read(self, n):
        if self.pos + n > len(self.data):
            raise ValueError('VARIANT data is truncated')
        res = self.data[self.pos:self.pos + n]
        self.pos += n
        return res

    def u16(self):
        self.align(2)
        return unpack('<H', self.read(2))[0]

    def u32(self):
        self.align(4)
        return unpack('<L', self.read(4))[0]

    def i32(self):
        self.align(4)
        return unpack('<l', self.read(4))[0]

    def bstr(self):
        # FLAGGED_WORD_BLOB: max count, cBytes, clSize, UTF-16LE code units
        self.u32()
        self.u32()
        size = self.u32()
        return self.read(size * 2).decode('utf-16-le')


def parse_variant(data):
    """
    Decodes an NDR marshalled VARIANT (as returned by GetConfigEntry).

    Supports the variant types a CA uses for registry values:
        REG_DWORD    -> VT_I4             -> int
        REG_SZ       -> VT_BSTR           -> str
        REG_MULTI_SZ -> VT_ARRAY|VT_BSTR  -> list of str
        REG_BINARY   -> VT_ARRAY|VT_UI1   -> bytes

    Args:
        data: wire bytes starting at the VARIANT's referent id

    Returns:
        (vt, value) tuple, value is None for VT_EMPTY/VT_NULL
    """
    r = _Reader(data)
    if r.u32() == 0:
        return VT_EMPTY, None

    r.align(8)
    r.u32()       # clSize
    r.u32()       # rpcReserved
    vt = r.u16()
    r.read(6)     # wReserved1-3
    r.u32()       # union tag, same as vt

    if vt in (VT_EMPTY, VT_NULL):
        return vt, None
    if vt == VT_I4:
        return vt, r.i32()
    if vt == VT_UI4:
        return vt, r.u32()
    if vt == VT_BSTR:
        if r.u32() == 0:
            return vt, None
        return vt, r.bstr()
    if vt & VT_ARRAY:
        if r.u32() == 0:  # PSAFEARRAY*
            return vt, None
        if r.u32() == 0:  # PSAFEARRAY
            return vt, None
        cdims = r.u32()   # conformance of rgsabound
        r.u16()           # cDims
        r.u16()           # fFeatures
        r.u32()           # cbElements
        r.u32()           # cLocks
        r.u32()           # SAFEARRAYUNION tag (sfType)
        r.u32()           # element count
        ptr = r.u32()     # pointer to the elements
        for _ in range(cdims):
            r.u32()       # cElements
            r.u32()       # lLbound

        elemtype = vt & ~VT_ARRAY
        if elemtype == VT_UI1:
            if ptr == 0:
                return vt, b''
            return vt, r.read(r.u32())
        if elemtype == VT_BSTR:
            if ptr == 0:
                return vt, []
            ptrs = [r.u32() for _ in range(r.u32())]
            return vt, [r.bstr() if p != 0 else '' for p in ptrs]

    raise NotImplementedError('Unsupported VARIANT type 0x%x' % vt)


def _variant_i4_body(value):
    """
    The VARIANT body (wireVARIANTStr, VT_I4) without the referent pointer.
    Must start on an 8-byte boundary. 24 bytes, matching clSize.
    """
    body = pack('<L', 24)                   # clSize: byte size of this struct
    body += pack('<L', 0)                   # rpcReserved
    body += pack('<H', int(VT_I4))          # vt
    body += b'\x00' * 6                      # wReserved1-3
    body += pack('<L', int(VT_I4))          # union tag (same as vt)
    body += pack('<L', value & 0xFFFFFFFF)  # lVal (bytes identical signed/unsigned)
    return body


def build_variant_i4(value, offset=0):
    """
    Marshals a 32-bit integer as an NDR VARIANT* (VT_I4), the inverse of
    parse_variant(). Used to pass a DWORD value to SetConfigEntry.

    The layout matches what parse_variant() reads back:
        [pre-pad] | referent id (4) | [pad] | clSize | rpcReserved | vt
        | wReserved1-3 | union tag | lVal

    NDR alignment is relative to the start of the stub, so the padding depends
    on where this blob lands. `offset` is the absolute byte offset at which the
    returned bytes are placed in the request: the referent is aligned to 4 and
    the VARIANT body to 8 relative to it. With the default offset=0 the result
    is referent + 4 pad + body, which round-trips through parse_variant().

    Args:
        value: the 32-bit integer to wrap
        offset: absolute offset of the blob in the request stub

    Returns:
        bytes of the marshalled VARIANT pointer
    """
    pre = (-offset) % 4                      # align the referent pointer to 4
    ref_off = offset + pre
    pad = (-(ref_off + 4)) % 8               # align the VARIANT body to 8
    out = b'\x00' * pre
    out += pack('<L', 0x00020000)            # referent id (non-NULL)
    out += b'\x00' * pad
    out += _variant_i4_body(value)
    return out


# =========================================================================
# ICertAdminD2 DCOM Interface
# =========================================================================

class ICertAdminD2(IRemUnknown):
    """
    ICertAdminD2 DCOM interface implementation for AD CS.

    Only the read-only methods are implemented:
    - ping: check that the CA service is reachable
    - get_my_roles: CA roles of the calling user
    - get_ca_security: CA security descriptor
    - get_ca_property: CA properties
    - get_config_entry: CA configuration (registry) values

    All methods take the CA name without the hostname (e.g. "MyCA").

    Usage:
        # After DCOM activation with CLSID_CCertAdminD
        async with ICertAdminD2(iInterface) as cert_admin:
            sd, err = await cert_admin.get_ca_security('MyCA')
            flags, err = await cert_admin.get_config_entry('MyCA', 'InterfaceFlags')
    """

    def __init__(self, interface):
        """
        Initialize ICertAdminD2 from an existing interface.

        Args:
            interface: INTERFACE instance from DCOM activation
        """
        IRemUnknown.__init__(self, interface)
        self._iid = IID_ICertAdminD2
        # CAs set IF_ENFORCEENCRYPTICERTADMIN by default and reply with
        # E_ACCESSDENIED to everything below packet privacy, while the
        # activation's authn hint only asks for integrity.
        self.get_cinstance().set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)

    async def ping(self, ca_name: str):
        """
        Checks that the CA service is up and responding.

        Returns:
            (True, None) on success
            (None, Exception) on failure
        """
        try:
            req = Ping()
            req['pwszAuthority'] = ca_name + '\x00'
            _, err = await self._request(req)
            if err is not None:
                raise err
            return True, None
        except Exception as e:
            return None, e

    async def get_my_roles(self, ca_name: str):
        """
        Retrieves the CA roles of the caller.

        Returns:
            (CAAccessMask, None) on success
            (None, Exception) on failure
        """
        try:
            req = GetMyRoles()
            req['pwszAuthority'] = ca_name + '\x00'
            resp, err = await self._request(req)
            if err is not None:
                raise err
            return CAAccessMask(resp['pdwRoles'] & 0xFFFFFFFF), None
        except Exception as e:
            return None, e

    async def get_ca_security(self, ca_name: str):
        """
        Retrieves the security descriptor of the CA.

        Returns:
            (sd_bytes, None) on success - self-relative security descriptor
            (None, Exception) on failure
        """
        try:
            req = GetCASecurity()
            req['pwszAuthority'] = ca_name + '\x00'
            resp, err = await self._request(req)
            if err is not None:
                raise err
            return b''.join(resp['pctbSD']['pbData']), None
        except Exception as e:
            return None, e

    async def get_ca_property(self, ca_name: str, prop_id: int, prop_type: int, prop_index: int = 0):
        """
        Retrieves a CA property.

        Args:
            ca_name: CA name
            prop_id: Property id (CR_PROP_*)
            prop_type: Type of the property (PROPTYPE_*), must match the property id
            prop_index: Index for indexed properties

        Returns:
            (value, None) on success. int for PROPTYPE_LONG, str for
                PROPTYPE_STRING, bytes otherwise
            (None, Exception) on failure
        """
        try:
            req = GetCAProperty()
            req['pwszAuthority'] = ca_name + '\x00'
            req['PropId'] = prop_id
            req['PropIndex'] = prop_index
            req['PropType'] = prop_type
            resp, err = await self._request(req)
            if err is not None:
                raise err

            data = b''.join(resp['pctbPropertyValue']['pbData'])
            if prop_type == PROPTYPE_LONG:
                if prop_id in CAINFO_OFFSETS and len(data) > CAINFO_OFFSETS[prop_id]:
                    data = data[CAINFO_OFFSETS[prop_id]:]
                return unpack('<l', data[:4])[0], None
            if prop_type == PROPTYPE_STRING:
                return data.decode('utf-16-le').rstrip('\x00'), None
            return data, None
        except Exception as e:
            return None, e

    async def get_config_entry(self, ca_name: str, entry: str, node_path: str = ''):
        """
        Retrieves a value from the CA's configuration.

        Args:
            ca_name: CA name. Empty string reads from the configuration root
                shared by all CAs on the server instead of the CA's own node.
            entry: Name of the value (e.g., 'InterfaceFlags')
            node_path: Path of the node holding the value, relative to the
                CA's configuration node (e.g., POLICY_MODULE_NODE)

        Returns:
            (value, None) on success. int, str, list of str or bytes
                depending on the type of the value
            (None, Exception) on failure
        """
        try:
            req = GetConfigEntry()
            req['pwszAuthority'] = ca_name + '\x00'
            req['pwszNodePath'] = node_path + '\x00'
            req['pwszEntry'] = entry + '\x00'

            logger.debug(f'Reading CA config entry: {ca_name}\\{node_path}\\{entry}')

            resp, err = await self._request(req)
            if err is not None:
                raise err

            _, value = parse_variant(resp['pVariant'])
            return value, None
        except Exception as e:
            return None, e

    async def set_config_entry_i4(self, ca_name: str, entry: str, value: int, node_path: str = ''):
        """
        Writes a DWORD (VT_I4) value into the CA's configuration.

        Args:
            ca_name: CA name
            entry: Name of the value (e.g., 'EditFlags')
            value: 32-bit integer to store
            node_path: Path of the node holding the value, relative to the CA's
                configuration node (e.g., POLICY_MODULE_NODE)

        Returns:
            (True, None) on success
            (None, Exception) on failure
        """
        try:
            req = SetConfigEntry()
            req['ORPCthis'] = self.get_cinstance().get_ORPCthis()
            req['pwszAuthority'] = ca_name + '\x00'
            req['pwszNodePath'] = node_path + '\x00'
            req['pwszEntry'] = entry + '\x00'
            # The raw VARIANT must honour NDR alignment relative to the stub.
            # Marshal with an empty placeholder to learn where it lands, then
            # build it with the matching padding. ORPCthis has a fixed size, so
            # the offset is stable even though request() regenerates it.
            req['pVariant'] = b''
            offset = len(req.getData())
            req['pVariant'] = build_variant_i4(value, offset=offset)

            logger.debug(f'Writing CA config entry: {ca_name}\\{node_path}\\{entry} = 0x{value & 0xFFFFFFFF:x}')

            resp, err = await self._request(req)
            if err is not None:
                raise err

            error_code = resp['ErrorCode'] & 0xFFFFFFFF
            if error_code != 0:
                raise DCERPCSessionError(error_code=error_code)
            return True, None
        except Exception as e:
            return None, e

    async def resubmit_request(self, ca_name: str, request_id: int):
        """
        Resubmits (issues) a pending request. Requires the Manage Certificates
        (CA officer) role.

        Args:
            ca_name: CA name
            request_id: Id of the pending request to issue

        Returns:
            (disposition, None) on success, disposition is a CR_DISP_* value
                (CR_DISP_ISSUED == 3 means the certificate was issued)
            (None, Exception) on failure
        """
        try:
            req = ResubmitRequest()
            req['pwszAuthority'] = ca_name + '\x00'
            req['dwRequestId'] = request_id

            resp, err = await self._request(req)
            if err is not None:
                raise err

            error_code = resp['ErrorCode'] & 0xFFFFFFFF
            if error_code != 0:
                raise DCERPCSessionError(error_code=error_code)
            return resp['pdwDisposition'] & 0xFFFFFFFF, None
        except Exception as e:
            return None, e

    async def _request(self, req):
        """
        Internal method to make DCOM requests on the ICertAdminD2 interface.
        """
        return await super().request(req, iid=self._iid, uuid=self.get_iPid())
