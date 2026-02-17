#!/usr/bin/env python3
"""
ShellWindows and ShellBrowserWindow DCOM Interfaces

Alternative DCOM execution methods using Windows Shell objects.

ShellWindows (CLSID: {9BA05972-F6A8-11CF-A442-00A0C90A8F39})
    - Provides access to the Shell.Windows collection
    - Can invoke ShellExecute via Document.Application.ShellExecute

ShellBrowserWindow (CLSID: {C08AFD90-F2A1-11D1-8455-00A0C91F3880})
    - Similar to ShellWindows but for browser windows
"""

from aiosmb.dcerpc.v5.dcom.remunknown import IRemUnknown
from aiosmb.dcerpc.v5.dcom.interface import INTERFACE
from aiosmb.dcerpc.v5.dcom.oaut import (
    IDispatch, IID_IDispatch, DISPATCH_PROPERTYGET, DISPATCH_METHOD,
)
from aiosmb.dcerpc.v5.uuid import string_to_bin


# CLSIDs
CLSID_ShellWindows = string_to_bin('9BA05972-F6A8-11CF-A442-00A0C90A8F39')
CLSID_ShellBrowserWindow = string_to_bin('C08AFD90-F2A1-11D1-8455-00A0C91F3880')


class ShellWindows(IRemUnknown):
    """
    ShellWindows COM Object wrapper.
    
    Provides command execution via the Shell.Windows collection.
    
    Usage:
        shell = ShellWindows(iInterface)
        await shell.ShellExecute('cmd.exe', '/c calc.exe', 'C:\\', '', 0)
    """
    
    def __init__(self, interface):
        IRemUnknown.__init__(self, interface)
        self._iid = IID_IDispatch
        self._dispatch = IDispatch(interface)
    
    async def ShellExecute(self, file: str, args: str = '', directory: str = 'C:\\Windows\\System32',
                           operation: str = 'open', show: int = 0):
        """
        Execute a command via ShellExecute.
        
        This method navigates through the COM object hierarchy:
            ShellWindows -> Item(0) -> Document -> Application -> ShellExecute
        
        Args:
            file: The executable to run (e.g., 'cmd.exe')
            args: Command line arguments
            directory: Working directory
            operation: Shell operation ('open', 'runas', etc.)
            show: Window show state (0=hidden, 1=normal)
        
        Returns:
            (result_dict, error) tuple where result_dict contains:
                - 'status': 0 on success (ShellExecute is void, so no return value)
                - 'error_code': The RPC error code from the response
                - 'exception_scode': HRESULT from exception info (if any)
                - 'exception_code': wCode from exception info (if any)
            
            Note: ShellExecute does NOT return a PID. The command is executed
                  asynchronously by the shell process.
        """
        try:
            # Step 1: Get Item(0) - first shell window
            itemDispId, err = await self._dispatch.pakIdOfName('Item')
            if err is not None:
                return None, Exception(f"Failed to get Item DISPID: {err}")
            
            # Invoke Item(0) - get the first shell window
            from aiosmb.dcerpc.v5.dcom.oaut import VARENUM
            result, err = await self._dispatch.pakInvoke(itemDispId, 0)
            if err is not None:
                return None, Exception(f"Failed to get Item(0): {err}")
            
            # Check result - pVarResult is wireVARIANTStr directly
            pVarResult = result['pVarResult']
            vt = pVarResult['vt']
            
            if vt == VARENUM.enumItems.VT_EMPTY or vt == VARENUM.enumItems.VT_NULL:
                return None, Exception("Item(0) returned null - no shell windows available")
            
            if vt != VARENUM.enumItems.VT_DISPATCH:
                return None, Exception(f"Item(0) returned unexpected type: {vt}")
            
            # Need to set the union tag to access the arm
            pVarResult['_varUnion']['tag'] = vt
            pdispVal = pVarResult['_varUnion']['pdispVal']
            
            # Check if the dispatch pointer is null (no explorer windows open)
            if pdispVal is None or len(b''.join(pdispVal['abData'])) < 4:
                return None, Exception("No explorer windows open on target. ShellWindows requires an existing explorer.exe shell window. Try ShellBrowserWindow instead.")
            
            itemInterface = INTERFACE(
                self._dispatch.get_cinstance(),
                b''.join(pdispVal['abData']),
                self._dispatch.get_ipidRemUnknown(),
                target=self._dispatch.get_target()
            )
            
            # Step 2: Get Document from the window
            windowDispatch = IDispatch(itemInterface)
            docDispId, err = await windowDispatch.pakIdOfName('Document')
            if err is not None:
                return None, Exception(f"Failed to get Document DISPID: {err}")
            
            docInterface, err = await windowDispatch.pakGet(docDispId)
            if err is not None:
                return None, Exception(f"Failed to get Document: {err}")
            
            # Step 3: Get Application from Document
            docDispatch = IDispatch(docInterface)
            appDispId, err = await docDispatch.pakIdOfName('Application')
            if err is not None:
                return None, Exception(f"Failed to get Application DISPID: {err}")
            
            appInterface, err = await docDispatch.pakGet(appDispId)
            if err is not None:
                return None, Exception(f"Failed to get Application: {err}")
            
            # Step 4: Call ShellExecute on Application
            appDispatch = IDispatch(appInterface)
            execDispId, err = await appDispatch.pakIdOfName('ShellExecute')
            if err is not None:
                return None, Exception(f"Failed to get ShellExecute DISPID: {err}")
            
            resp, err = await appDispatch.pakInvoke(
                execDispId, file, args, directory, operation, show
            )
            if err is not None:
                return None, Exception(f"ShellExecute failed: {err}")
            
            # Extract status information from the response
            result = {
                'status': 0,  # ShellExecute is void, 0 means call succeeded
                'error_code': resp['ErrorCode'] if resp and 'ErrorCode' in resp.fields else 0,
            }
            
            # Extract exception info if available
            if resp and 'pExcepInfo' in resp.fields:
                excep_info = resp['pExcepInfo']
                result['exception_scode'] = excep_info['scode'] if 'scode' in excep_info.fields else 0
                result['exception_code'] = excep_info['wCode'] if 'wCode' in excep_info.fields else 0
            
            return result, None
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            return None, e


class ShellBrowserWindow(IRemUnknown):
    """
    ShellBrowserWindow COM Object wrapper.
    
    Similar to ShellWindows but creates a new browser window context.
    """
    
    def __init__(self, interface):
        IRemUnknown.__init__(self, interface)
        self._iid = IID_IDispatch
        self._dispatch = IDispatch(interface)
    
    async def ShellExecute(self, file: str, args: str = '', directory: str = 'C:\\Windows\\System32',
                           operation: str = 'open', show: int = 0):
        """
        Execute a command via ShellExecute.
        
        ShellBrowserWindow provides direct access to Document.Application.
        
        Args:
            file: The executable to run
            args: Command line arguments
            directory: Working directory
            operation: Shell operation
            show: Window show state
        
        Returns:
            (result_dict, error) tuple where result_dict contains:
                - 'status': 0 on success (ShellExecute is void, so no return value)
                - 'error_code': The RPC error code from the response
                - 'exception_scode': HRESULT from exception info (if any)
                - 'exception_code': wCode from exception info (if any)
            
            Note: ShellExecute does NOT return a PID. The command is executed
                  asynchronously by the shell process.
        """
        try:
            # Step 1: Get Document
            docDispId, err = await self._dispatch.pakIdOfName('Document')
            if err is not None:
                return None, Exception(f"Failed to get Document DISPID: {err}")
            
            docInterface, err = await self._dispatch.pakGet(docDispId)
            if err is not None:
                return None, Exception(f"Failed to get Document: {err}")
            
            # Step 2: Get Application from Document
            docDispatch = IDispatch(docInterface)
            appDispId, err = await docDispatch.pakIdOfName('Application')
            if err is not None:
                return None, Exception(f"Failed to get Application DISPID: {err}")
            
            appInterface, err = await docDispatch.pakGet(appDispId)
            if err is not None:
                return None, Exception(f"Failed to get Application: {err}")
            
            # Step 3: Call ShellExecute
            appDispatch = IDispatch(appInterface)
            execDispId, err = await appDispatch.pakIdOfName('ShellExecute')
            if err is not None:
                return None, Exception(f"Failed to get ShellExecute DISPID: {err}")
            
            resp, err = await appDispatch.pakInvoke(
                execDispId, file, args, directory, operation, show
            )
            if err is not None:
                return None, Exception(f"ShellExecute failed: {err}")
            
            # Extract status information from the response
            result = {
                'status': 0,  # ShellExecute is void, 0 means call succeeded
                'error_code': resp['ErrorCode'] if resp and 'ErrorCode' in resp.fields else 0,
            }
            
            # Extract exception info if available
            if resp and 'pExcepInfo' in resp.fields:
                excep_info = resp['pExcepInfo']
                result['exception_scode'] = excep_info['scode'] if 'scode' in excep_info.fields else 0
                result['exception_code'] = excep_info['wCode'] if 'wCode' in excep_info.fields else 0
            
            return result, None
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            return None, e
