# Async DCOM Activation interfaces for aiosmb
#
# Implements IActivation and IRemoteSCMActivator for creating
# remote COM objects.
#

from struct import pack

from aiosmb import logger
from aiosmb.dcerpc.v5.connection import DCERPC5Connection
from aiosmb.dcerpc.v5.dtypes import NULL
from aiosmb.dcerpc.v5.uuid import generate

from aiosmb.dcerpc.v5.dcom.dcomrt import (
    # IIDs
    IID_IActivation, IID_IRemoteSCMActivator,
    IID_IActivationPropertiesIn, IID_IActivationPropertiesOut,
    
    # CLSIDs
    CLSID_ActivationPropertiesIn, CLSID_InstantiationInfo,
    CLSID_ActivationContextInfo, CLSID_ServerLocationInfo,
    CLSID_ScmRequestInfo,
    
    # Structures
    ORPCTHIS, ORPCTHAT, IID, CLSID, DWORD,
    OBJREF, OBJREF_STANDARD, OBJREF_HANDLER, OBJREF_CUSTOM, OBJREF_EXTENDED,
    FLAGS_OBJREF_STANDARD, FLAGS_OBJREF_HANDLER, FLAGS_OBJREF_CUSTOM, FLAGS_OBJREF_EXTENDED,
    STRINGBINDING, SECURITYBINDING,
    ACTIVATION_BLOB, CustomHeader, PropsOutInfo, ScmReplyInfoData,
    InstantiationInfoData, ActivationContextInfoData, LocationInfoData, ScmRequestInfoData,
    
    # RPC Calls
    RemoteActivation, RemoteActivationResponse,
    RemoteGetClassObject, RemoteGetClassObjectResponse,
    RemoteCreateInstance, RemoteCreateInstanceResponse,
)
from aiosmb.dcerpc.v5.dcom.interface import INTERFACE, CLASS_INSTANCE


class IActivation:
    """
    IActivation interface implementation.
    
    Provides the RemoteActivation method for creating COM objects
    using the older activation protocol.
    """
    
    def __init__(self, dce: DCERPC5Connection, target: str):
        """
        Initialize IActivation.
        
        Args:
            dce: DCE/RPC connection (to port 135)
            target: Target hostname/IP
        """
        self._portmap = dce
        self._target = target
    
    async def RemoteActivation(self, clsId, iid):
        """
        Activate a remote COM object.
        
        Args:
            clsId: Class ID (CLSID) of the object to create
            iid: Interface ID (IID) to query
        
        Returns:
            (IRemUnknown2 interface, None) on success
            (None, Exception) on failure
        """
        try:
            # Import here to avoid circular imports
            from aiosmb.dcerpc.v5.dcom.remunknown import IRemUnknown2
            
            _, err = await self._portmap.bind(IID_IActivation)
            if err is not None:
                raise err
            
            # Build ORPC header
            ORPCthis = ORPCTHIS()
            ORPCthis['cid'] = generate()
            ORPCthis['extensions'] = NULL
            ORPCthis['flags'] = 1
            
            request = RemoteActivation()
            request['ORPCthis'] = ORPCthis
            request['Clsid'] = clsId
            request['pwszObjectName'] = NULL
            request['pObjectStorage'] = NULL
            request['ClientImpLevel'] = 2
            request['Mode'] = 0
            request['Interfaces'] = 1
            
            _iid = IID()
            _iid['Data'] = iid
            request['pIIDs'].append(_iid)
            
            request['cRequestedProtseqs'] = 1
            request['aRequestedProtseqs'].append(7)  # TCP
            
            resp, err = await self._portmap.request(request)
            if err is not None:
                raise err
            
            # Parse response
            ipidRemUnknown = resp['pipidRemUnknown']
            
            # Parse string bindings
            oxids = b''.join(pack('<H', x) for x in resp['ppdsaOxidBindings']['aStringArray'])
            str_bindings = oxids[:resp['ppdsaOxidBindings']['wSecurityOffset'] * 2]
            sec_bindings = oxids[resp['ppdsaOxidBindings']['wSecurityOffset'] * 2:]
            
            string_bindings = []
            while len(str_bindings) >= 4:
                if str_bindings[0:2] == b'\x00\x00':
                    break
                binding = STRINGBINDING(str_bindings)
                string_bindings.append(binding)
                str_bindings = str_bindings[len(binding):]
            
            # Parse security bindings (we don't use them but need to consume)
            while len(sec_bindings) >= 4:
                if sec_bindings[0:2] == b'\x00\x00':
                    break
                sec_binding = SECURITYBINDING(sec_bindings)
                sec_bindings = sec_bindings[len(sec_binding):]
            
            # Create class instance
            class_instance = CLASS_INSTANCE(ORPCthis, string_bindings)
            
            # Build interface
            interface_data = b''.join(resp['ppInterfaceData'][0]['abData'])
            interface = INTERFACE(
                class_instance,
                interface_data,
                ipidRemUnknown,
                target=self._target
            )
            
            return IRemUnknown2(interface), None
            
        except Exception as e:
            return None, e


class IRemoteSCMActivator:
    """
    IRemoteSCMActivator interface implementation.
    
    Provides RemoteGetClassObject and RemoteCreateInstance methods
    for creating COM objects using the newer SCM activation protocol.
    """
    
    def __init__(self, dce: DCERPC5Connection, target: str):
        """
        Initialize IRemoteSCMActivator.
        
        Args:
            dce: DCE/RPC connection (to port 135)
            target: Target hostname/IP
        """
        self._portmap = dce
        self._target = target
    
    def _build_activation_blob(self, clsId, iid):
        """Build the activation properties blob"""
        activation_blob = ACTIVATION_BLOB()
        activation_blob['CustomHeader']['destCtx'] = 2
        activation_blob['CustomHeader']['pdwReserved'] = NULL
        
        # Add CLSIDs for properties
        clsid = CLSID()
        clsid['Data'] = CLSID_InstantiationInfo
        activation_blob['CustomHeader']['pclsid'].append(clsid)
        
        clsid = CLSID()
        clsid['Data'] = CLSID_ActivationContextInfo
        activation_blob['CustomHeader']['pclsid'].append(clsid)
        
        clsid = CLSID()
        clsid['Data'] = CLSID_ServerLocationInfo
        activation_blob['CustomHeader']['pclsid'].append(clsid)
        
        clsid = CLSID()
        clsid['Data'] = CLSID_ScmRequestInfo
        activation_blob['CustomHeader']['pclsid'].append(clsid)
        
        properties = b''
        
        # InstantiationInfo
        instantiation_info = InstantiationInfoData()
        instantiation_info['classId'] = clsId
        instantiation_info['cIID'] = 1
        
        _iid = IID()
        _iid['Data'] = iid
        instantiation_info['pIID'].append(_iid)
        
        dword = DWORD()
        marshaled = instantiation_info.getData() + instantiation_info.getDataReferents()
        pad = (8 - (len(marshaled) % 8)) % 8
        dword['Data'] = len(marshaled) + pad
        activation_blob['CustomHeader']['pSizes'].append(dword)
        instantiation_info['thisSize'] = dword['Data']
        
        properties += marshaled + b'\xFA' * pad
        
        # ActivationContextInfoData
        activation_info = ActivationContextInfoData()
        activation_info['pIFDClientCtx'] = NULL
        activation_info['pIFDPrototypeCtx'] = NULL
        
        dword = DWORD()
        marshaled = activation_info.getData() + activation_info.getDataReferents()
        pad = (8 - (len(marshaled) % 8)) % 8
        dword['Data'] = len(marshaled) + pad
        activation_blob['CustomHeader']['pSizes'].append(dword)
        
        properties += marshaled + b'\xFA' * pad
        
        # ServerLocation
        location_info = LocationInfoData()
        location_info['machineName'] = NULL
        
        dword = DWORD()
        dword['Data'] = len(location_info.getData())
        activation_blob['CustomHeader']['pSizes'].append(dword)
        
        properties += location_info.getData() + location_info.getDataReferents()
        
        # ScmRequestInfo
        scm_info = ScmRequestInfoData()
        scm_info['pdwReserved'] = NULL
        scm_info['remoteRequest']['cRequestedProtseqs'] = 1
        scm_info['remoteRequest']['pRequestedProtseqs'].append(7)  # TCP
        
        dword = DWORD()
        marshaled = scm_info.getData() + scm_info.getDataReferents()
        pad = (8 - (len(marshaled) % 8)) % 8
        dword['Data'] = len(marshaled) + pad
        activation_blob['CustomHeader']['pSizes'].append(dword)
        
        properties += marshaled + b'\xFA' * pad
        
        activation_blob['Property'] = properties
        
        return activation_blob
    
    def _parse_activation_response(self, resp, ORPCthis):
        """Parse the activation response and build interface"""
        from aiosmb.dcerpc.v5.dcom.remunknown import IRemUnknown2
        
        # Parse OBJREF type
        objRefType = OBJREF(b''.join(resp['ppActProperties']['abData']))['flags']
        objRef = None
        
        if objRefType == FLAGS_OBJREF_CUSTOM:
            objRef = OBJREF_CUSTOM(b''.join(resp['ppActProperties']['abData']))
        elif objRefType == FLAGS_OBJREF_HANDLER:
            objRef = OBJREF_HANDLER(b''.join(resp['ppActProperties']['abData']))
        elif objRefType == FLAGS_OBJREF_STANDARD:
            objRef = OBJREF_STANDARD(b''.join(resp['ppActProperties']['abData']))
        elif objRefType == FLAGS_OBJREF_EXTENDED:
            objRef = OBJREF_EXTENDED(b''.join(resp['ppActProperties']['abData']))
        else:
            raise ValueError(f"Unknown OBJREF Type: 0x{objRefType:x}")
        
        # Parse activation blob from response
        activation_blob = ACTIVATION_BLOB(objRef['pObjectData'])
        
        prop_output = activation_blob['Property'][:activation_blob['CustomHeader']['pSizes'][0]['Data']]
        scm_reply = activation_blob['Property'][
            activation_blob['CustomHeader']['pSizes'][0]['Data']:
            activation_blob['CustomHeader']['pSizes'][0]['Data'] + 
            activation_blob['CustomHeader']['pSizes'][1]['Data']
        ]
        
        # Parse SCM reply
        scmr = ScmReplyInfoData()
        size = scmr.fromString(scm_reply)
        scmr.fromStringReferents(scm_reply[size:])
        
        ipidRemUnknown = scmr['remoteReply']['ipidRemUnknown']
        
        # Parse string bindings
        oxids = b''.join(pack('<H', x) for x in scmr['remoteReply']['pdsaOxidBindings']['aStringArray'])
        str_bindings = oxids[:scmr['remoteReply']['pdsaOxidBindings']['wSecurityOffset'] * 2]
        sec_bindings = oxids[scmr['remoteReply']['pdsaOxidBindings']['wSecurityOffset'] * 2:]
        
        string_bindings = []
        while len(str_bindings) >= 4:
            if str_bindings[0:2] == b'\x00\x00':
                break
            binding = STRINGBINDING(str_bindings)
            string_bindings.append(binding)
            str_bindings = str_bindings[len(binding):]
        
        while len(sec_bindings) >= 4:
            if sec_bindings[0:2] == b'\x00\x00':
                break
            sec_binding = SECURITYBINDING(sec_bindings)
            sec_bindings = sec_bindings[len(sec_binding):]
        
        # Parse properties output
        props_out = PropsOutInfo()
        size = props_out.fromString(prop_output)
        props_out.fromStringReferents(prop_output[size:])
        
        # Create class instance
        class_instance = CLASS_INSTANCE(ORPCthis, string_bindings)
        class_instance.set_auth_level(scmr['remoteReply']['authnHint'])
        class_instance.set_auth_type(self._portmap.auth_type)
        
        # Build interface
        interface_data = b''.join(props_out['ppIntfData'][0]['abData'])
        interface = INTERFACE(
            class_instance,
            interface_data,
            ipidRemUnknown,
            target=self._target
        )
        
        return IRemUnknown2(interface)
    
    async def RemoteGetClassObject(self, clsId, iid):
        """
        Get a class factory object.
        
        Args:
            clsId: Class ID (CLSID) of the class factory
            iid: Interface ID (IID), typically IID_IClassFactory
        
        Returns:
            (IRemUnknown2 interface, None) on success
            (None, Exception) on failure
        """
        try:
            _, err = await self._portmap.bind(IID_IRemoteSCMActivator)
            if err is not None:
                raise err
            
            # Build ORPC header
            ORPCthis = ORPCTHIS()
            ORPCthis['cid'] = generate()
            ORPCthis['extensions'] = NULL
            ORPCthis['flags'] = 1
            
            request = RemoteGetClassObject()
            request['ORPCthis'] = ORPCthis
            
            # Build activation blob
            activation_blob = self._build_activation_blob(clsId, iid)
            
            # Build OBJREF_CUSTOM wrapper
            objref_custom = OBJREF_CUSTOM()
            objref_custom['iid'] = IID_IActivationPropertiesIn[:-4]
            objref_custom['clsid'] = CLSID_ActivationPropertiesIn
            objref_custom['pObjectData'] = activation_blob.getData()
            objref_custom['ObjectReferenceSize'] = len(objref_custom['pObjectData']) + 8
            
            request['pActProperties']['ulCntData'] = len(objref_custom.getData())
            request['pActProperties']['abData'] = list(objref_custom.getData())
            
            resp, err = await self._portmap.request(request)
            if err is not None:
                raise err
            
            return self._parse_activation_response(resp, ORPCthis), None
            
        except Exception as e:
            return None, e
    
    async def RemoteCreateInstance(self, clsId, iid):
        """
        Create an instance of a COM object.
        
        Args:
            clsId: Class ID (CLSID) of the object to create
            iid: Interface ID (IID) to query
        
        Returns:
            (IRemUnknown2 interface, None) on success
            (None, Exception) on failure
        """
        try:
            _, err = await self._portmap.bind(IID_IRemoteSCMActivator)
            if err is not None:
                raise err
            
            # Build ORPC header
            ORPCthis = ORPCTHIS()
            ORPCthis['cid'] = generate()
            ORPCthis['extensions'] = NULL
            ORPCthis['flags'] = 1
            
            request = RemoteCreateInstance()
            request['ORPCthis'] = ORPCthis
            request['pUnkOuter'] = NULL
            
            # Build activation blob
            activation_blob = self._build_activation_blob(clsId, iid)
            
            # Build OBJREF_CUSTOM wrapper
            objref_custom = OBJREF_CUSTOM()
            objref_custom['iid'] = IID_IActivationPropertiesIn[:-4]
            objref_custom['clsid'] = CLSID_ActivationPropertiesIn
            objref_custom['pObjectData'] = activation_blob.getData()
            objref_custom['ObjectReferenceSize'] = len(objref_custom['pObjectData']) + 8
            
            request['pActProperties']['ulCntData'] = len(objref_custom.getData())
            request['pActProperties']['abData'] = list(objref_custom.getData())
            
            resp, err = await self._portmap.request(request)
            if err is not None:
                raise err
            
            return self._parse_activation_response(resp, ORPCthis), None
            
        except Exception as e:
            return None, e
