# DCOM (Distributed Component Object Model) implementation for aiosmb
# 
# This module provides async DCOM/RPC functionality based on [MS-DCOM] specification.
# Ported from impacket's dcomrt.py with modifications for async/await patterns.
#
# Key components:
#   - DCOMConnection: Main connection class for DCOM operations
#   - IObjectExporter: Object lifetime management (ping mechanism)
#   - IRemoteSCMActivator: Remote COM object activation
#   - IRemUnknown/IRemUnknown2: Remote interface management
#   - WMI interfaces: IWbemLevel1Login, IWbemServices, IWbemClassObject
#

from aiosmb.dcerpc.v5.dcom.dcomrt import *
from aiosmb.dcerpc.v5.dcom.connection import DCOMConnection
from aiosmb.dcerpc.v5.dcom.interface import INTERFACE, CLASS_INSTANCE
from aiosmb.dcerpc.v5.dcom.objectexporter import IObjectExporter
from aiosmb.dcerpc.v5.dcom.activation import IActivation, IRemoteSCMActivator
from aiosmb.dcerpc.v5.dcom.remunknown import IRemUnknown, IRemUnknown2

# WMI (Windows Management Instrumentation) imports
from aiosmb.dcerpc.v5.dcom.wmi import (
    # CLSIDs and IIDs
    CLSID_WbemLevel1Login,
    CLSID_WbemClassObject,
    IID_IWbemLevel1Login,
    IID_IWbemServices,
    IID_IEnumWbemClassObject,
    IID_IWbemClassObject,
    # Status codes
    WBEMSTATUS,
    WMISessionError,
    # Flags
    WBEM_FLAG_FORWARD_ONLY,
    WBEM_FLAG_RETURN_IMMEDIATELY,
    WBEM_INFINITE,
    # Interface classes
    IWbemLevel1Login,
    IWbemServices,
    IWbemClassObject,
    IEnumWbemClassObject,
    IWbemCallResult,
    IWbemLoginClientID,
)

# AD CS (Active Directory Certificate Services) imports
from aiosmb.dcerpc.v5.dcom.certreq import (
    # CLSIDs and IIDs
    CLSID_ICertRequest,
    IID_ICertRequestD,
    # Disposition codes
    CR_DISP_INCOMPLETE,
    CR_DISP_ERROR,
    CR_DISP_DENIED,
    CR_DISP_ISSUED,
    CR_DISP_ISSUED_OUT_OF_BAND,
    CR_DISP_UNDER_SUBMISSION,
    CR_DISP_REVOKED,
    DISPOSITION_NAMES,
    # Request flags
    CR_IN_BASE64HEADER,
    CR_IN_BASE64,
    CR_IN_BINARY,
    CR_IN_ENCODEANY,
    CR_IN_PKCS10,
    CR_IN_KEYGEN,
    CR_IN_PKCS7,
    CR_IN_CMC,
    CR_IN_RPC,
    # Interface class
    ICertRequestD,
)