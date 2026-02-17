# Async IObjectExporter implementation for aiosmb
#
# Implements the IObjectExporter interface for DCOM object lifetime management.
# This interface is used for ping operations to keep remote objects alive.
#

from struct import pack

from aiosmb.dcerpc.v5.connection import DCERPC5Connection
from aiosmb.dcerpc.v5.dtypes import NULL

from aiosmb.dcerpc.v5.dcom.dcomrt import (
    IID_IObjectExporter,
    ResolveOxid, ResolveOxidResponse,
    SimplePing, SimplePingResponse,
    ComplexPing, ComplexPingResponse,
    ServerAlive, ServerAliveResponse,
    ResolveOxid2, ResolveOxid2Response,
    ServerAlive2, ServerAlive2Response,
    STRINGBINDING, OID,
)


class IObjectExporter:
    """
    IObjectExporter interface implementation.
    
    This interface provides methods for:
    - Resolving OXIDs to network addresses
    - Keeping objects alive via ping operations
    - Checking server availability
    
    Used internally by the DCOMConnectionManager for keep-alive pinging.
    """
    
    def __init__(self, dce: DCERPC5Connection):
        """
        Initialize IObjectExporter.
        
        Args:
            dce: DCE/RPC connection (typically to port 135)
        """
        self._portmap = dce
    
    async def _ensure_bound(self):
        """Ensure we're connected and bound to IObjectExporter"""
        # Note: The connection should already be established
        # We just need to bind to the correct interface
        _, err = await self._portmap.bind(IID_IObjectExporter)
        return err
    
    async def ResolveOxid(self, pOxid, arRequestedProtseqs):
        """
        Resolve an OXID to network bindings.
        
        Args:
            pOxid: Object Exporter ID to resolve
            arRequestedProtseqs: List of requested protocol sequences (e.g., [7] for TCP)
        
        Returns:
            (list of STRINGBINDING, None) on success
            (None, Exception) on failure
        """
        try:
            err = await self._ensure_bound()
            if err is not None:
                raise err
            
            request = ResolveOxid()
            request['pOxid'] = pOxid
            request['cRequestedProtseqs'] = len(arRequestedProtseqs)
            for protSeq in arRequestedProtseqs:
                request['arRequestedProtseqs'].append(protSeq)
            
            resp, err = await self._portmap.request(request)
            if err is not None:
                raise err
            
            # Parse the bindings
            oxids = b''.join(pack('<H', x) for x in resp['ppdsaOxidBindings']['aStringArray'])
            str_bindings = oxids[:resp['ppdsaOxidBindings']['wSecurityOffset'] * 2]
            
            string_bindings = []
            while len(str_bindings) >= 4:
                if str_bindings[0:2] == b'\x00\x00':
                    break
                binding = STRINGBINDING(str_bindings)
                string_bindings.append(binding)
                str_bindings = str_bindings[len(binding):]
            
            return string_bindings, None
            
        except Exception as e:
            return None, e
    
    async def SimplePing(self, setId):
        """
        Send a simple ping to keep objects alive.
        
        Args:
            setId: Set ID returned from a previous ComplexPing
        
        Returns:
            (response, None) on success
            (None, Exception) on failure
        """
        try:
            err = await self._ensure_bound()
            if err is not None:
                raise err
            
            request = SimplePing()
            request['pSetId'] = setId
            
            resp, err = await self._portmap.request(request)
            if err is not None:
                raise err
            
            return resp, None
            
        except Exception as e:
            return None, e
    
    async def ComplexPing(self, setId=0, sequenceNum=0, addToSet=None, delFromSet=None):
        """
        Send a complex ping to add/remove objects from the ping set.
        
        Args:
            setId: Existing set ID (0 to create new set)
            sequenceNum: Sequence number for the ping
            addToSet: Set of OIDs to add to the ping set
            delFromSet: Set of OIDs to remove from the ping set
        
        Returns:
            (response with new setId, None) on success
            (None, Exception) on failure
        """
        try:
            if addToSet is None:
                addToSet = set()
            if delFromSet is None:
                delFromSet = set()
            
            err = await self._ensure_bound()
            if err is not None:
                raise err
            
            request = ComplexPing()
            request['pSetId'] = setId
            request['SequenceNum'] = sequenceNum
            request['cAddToSet'] = len(addToSet)
            request['cDelFromSet'] = len(delFromSet)
            
            if len(addToSet) > 0:
                for oid in addToSet:
                    oidn = OID()
                    oidn['Data'] = oid
                    request['AddToSet'].append(oidn)
            else:
                request['AddToSet'] = NULL
            
            if len(delFromSet) > 0:
                for oid in delFromSet:
                    oidn = OID()
                    oidn['Data'] = oid
                    request['DelFromSet'].append(oidn)
            else:
                request['DelFromSet'] = NULL
            
            resp, err = await self._portmap.request(request)
            if err is not None:
                raise err
            
            return resp, None
            
        except Exception as e:
            return None, e
    
    async def ServerAlive(self):
        """
        Check if the server is alive.
        
        Returns:
            (response, None) on success
            (None, Exception) on failure
        """
        try:
            err = await self._ensure_bound()
            if err is not None:
                raise err
            
            request = ServerAlive()
            resp, err = await self._portmap.request(request)
            if err is not None:
                raise err
            
            return resp, None
            
        except Exception as e:
            return None, e
    
    async def ResolveOxid2(self, pOxid, arRequestedProtseqs):
        """
        Resolve an OXID to network bindings (extended version).
        
        Args:
            pOxid: Object Exporter ID to resolve
            arRequestedProtseqs: List of requested protocol sequences
        
        Returns:
            (list of STRINGBINDING, None) on success
            (None, Exception) on failure
        """
        try:
            err = await self._ensure_bound()
            if err is not None:
                raise err
            
            request = ResolveOxid2()
            request['pOxid'] = pOxid
            request['cRequestedProtseqs'] = len(arRequestedProtseqs)
            for protSeq in arRequestedProtseqs:
                request['arRequestedProtseqs'].append(protSeq)
            
            resp, err = await self._portmap.request(request)
            if err is not None:
                raise err
            
            # Parse the bindings
            oxids = b''.join(pack('<H', x) for x in resp['ppdsaOxidBindings']['aStringArray'])
            str_bindings = oxids[:resp['ppdsaOxidBindings']['wSecurityOffset'] * 2]
            
            string_bindings = []
            while len(str_bindings) >= 4:
                if str_bindings[0:2] == b'\x00\x00':
                    break
                binding = STRINGBINDING(str_bindings)
                string_bindings.append(binding)
                str_bindings = str_bindings[len(binding):]
            
            return string_bindings, None
            
        except Exception as e:
            return None, e
    
    async def ServerAlive2(self):
        """
        Check if the server is alive (extended version with bindings).
        
        Returns:
            (list of STRINGBINDING, None) on success
            (None, Exception) on failure
        """
        try:
            err = await self._ensure_bound()
            if err is not None:
                raise err
            
            request = ServerAlive2()
            resp, err = await self._portmap.request(request)
            if err is not None:
                raise err
            
            # Parse the bindings
            oxids = b''.join(pack('<H', x) for x in resp['ppdsaOrBindings']['aStringArray'])
            str_bindings = oxids[:resp['ppdsaOrBindings']['wSecurityOffset'] * 2]
            
            string_bindings = []
            while len(str_bindings) >= 4:
                if str_bindings[0:2] == b'\x00\x00':
                    break
                binding = STRINGBINDING(str_bindings)
                string_bindings.append(binding)
                str_bindings = str_bindings[len(binding):]
            
            return string_bindings, None
            
        except Exception as e:
            return None, e
