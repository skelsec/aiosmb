# Async IRemUnknown/IRemUnknown2 implementation for aiosmb
#
# Implements the IRemUnknown interface for remote COM interface management.
# This is the base interface for all remote COM objects.
#

from aiosmb.dcerpc.v5.dcom.dcomrt import (
    IID_IRemUnknown, IID_IRemUnknown2, IID,
    RemQueryInterface, RemQueryInterfaceResponse,
    RemAddRef, RemAddRefResponse,
    RemRelease, RemReleaseResponse,
    REMINTERFACEREF,
)
from aiosmb.dcerpc.v5.dcom.interface import INTERFACE
from aiosmb.dcerpc.v5.dcom.connection import DCOMConnectionManager


class IRemUnknown(INTERFACE):
    """
    IRemUnknown interface implementation.
    
    This is the remote equivalent of IUnknown and provides:
    - RemQueryInterface: Query for additional interfaces
    - RemAddRef: Add a reference to an interface
    - RemRelease: Release an interface reference
    
    All DCOM interface proxies ultimately inherit from this class.
    
    Supports async context manager for automatic resource cleanup:
        async with iWbemServices:
            # use the interface...
        # RemRelease() is called automatically
    """
    
    def __init__(self, interface):
        """
        Initialize IRemUnknown from an existing interface.
        
        Args:
            interface: INTERFACE instance to wrap
        """
        self._iid = IID_IRemUnknown
        self._released = False
        INTERFACE.__init__(self, interfaceInstance=interface)
        self.set_oxid(interface.get_oxid())
    
    async def __aenter__(self):
        """
        Async context manager entry.
        
        Returns self for use in 'async with' statements.
        """
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """
        Async context manager exit.
        
        Automatically calls RemRelease() to clean up the interface.
        Exceptions during release are silently ignored to avoid
        masking the original exception (if any).
        """
        if not self._released:
            try:
                await self.RemRelease()
            except Exception:
                # Don't mask the original exception
                pass
        return False  # Don't suppress exceptions
    
    async def RemQueryInterface(self, cRefs, iids):
        """
        Query for additional interfaces on this object.
        
        Args:
            cRefs: Reference count for the new interfaces
            iids: List of Interface IDs to query
        
        Returns:
            (IRemUnknown2 interface, None) on success
            (None, Exception) on failure
        """
        try:
            request = RemQueryInterface()
            request['ORPCthis'] = self.get_cinstance().get_ORPCthis()
            request['ORPCthis']['flags'] = 0
            request['ripid'] = self.get_iPid()
            request['cRefs'] = cRefs
            request['cIids'] = len(iids)
            
            for iid in iids:
                _iid = IID()
                _iid['Data'] = iid
                request['iids'].append(_iid)
            
            resp, err = await self.request(request, IID_IRemUnknown, self.get_ipidRemUnknown())
            if err is not None:
                raise err
            
            # Build new interface from response
            new_interface = INTERFACE(
                self.get_cinstance(),
                None,
                self.get_ipidRemUnknown(),
                resp['ppQIResults']['std']['ipid'],
                oxid=resp['ppQIResults']['std']['oxid'],
                oid=resp['ppQIResults']['std']['oid'],
                target=self.get_target()
            )
            
            return IRemUnknown2(new_interface), None
            
        except Exception as e:
            return None, e
    
    async def RemAddRef(self):
        """
        Add a reference to this interface.
        
        Returns:
            (response, None) on success
            (None, Exception) on failure
        """
        try:
            request = RemAddRef()
            request['ORPCthis'] = self.get_cinstance().get_ORPCthis()
            request['ORPCthis']['flags'] = 0
            request['cInterfaceRefs'] = 1
            
            element = REMINTERFACEREF()
            element['ipid'] = self.get_iPid()
            element['cPublicRefs'] = 1
            request['InterfaceRefs'].append(element)
            
            resp, err = await self.request(request, IID_IRemUnknown, self.get_ipidRemUnknown())
            if err is not None:
                raise err
            
            return resp, None
            
        except Exception as e:
            return None, e
    
    async def RemRelease(self):
        """
        Release this interface reference.
        
        This should be called when done with the interface to allow
        the server to clean up the object.
        
        Note: If using 'async with', this is called automatically on exit.
        
        Returns:
            (response, None) on success
            (None, Exception) on failure
        """
        # Prevent double-release
        if self._released:
            return None, None
        
        try:
            request = RemRelease()
            request['ORPCthis'] = self.get_cinstance().get_ORPCthis()
            request['ORPCthis']['flags'] = 0
            request['cInterfaceRefs'] = 1
            
            element = REMINTERFACEREF()
            element['ipid'] = self.get_iPid()
            element['cPublicRefs'] = 1
            request['InterfaceRefs'].append(element)
            
            resp, err = await self.request(request, IID_IRemUnknown, self.get_ipidRemUnknown())
            if err is not None:
                raise err
            
            # Mark as released
            self._released = True
            
            # Remove OID from ping set
            manager = DCOMConnectionManager.get_instance()
            await manager.del_oid(self.get_target(), self.get_oid())
            
            return resp, None
            
        except Exception as e:
            return None, e


class IRemUnknown2(IRemUnknown):
    """
    IRemUnknown2 interface implementation.
    
    This is an extended version of IRemUnknown that is typically
    returned from activation calls. It provides the same methods
    as IRemUnknown but uses IID_IRemUnknown2 for binding.
    
    Most DCOM objects will be accessed through IRemUnknown2.
    """
    
    def __init__(self, interface):
        """
        Initialize IRemUnknown2 from an existing interface.
        
        Args:
            interface: INTERFACE instance to wrap
        """
        IRemUnknown.__init__(self, interface)
        self._iid = IID_IRemUnknown2
