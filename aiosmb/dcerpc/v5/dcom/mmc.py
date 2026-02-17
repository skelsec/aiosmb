#!/usr/bin/env python3
"""
MMC20.Application DCOM Interface

This module implements the MMC20.Application COM object which provides
command execution capability via the ExecuteShellCommand method.

Reference:
    - CLSID: {49B2791A-B1AE-4C90-9B8E-E860BA07F889}
    - ProgID: MMC20.Application

The MMC20.Application object exposes:
    - Document property -> returns MMCDocument
    - MMCDocument.ActiveView -> returns View
    - View.ExecuteShellCommand(Command, Directory, Parameters, WindowState)

WindowState values:
    - "Minimized" = 0
    - "Maximized" = 1  
    - "Restored" = 2 (normal window)
"""

from aiosmb.dcerpc.v5.dcom.remunknown import IRemUnknown
from aiosmb.dcerpc.v5.dcom.oaut import (
    IDispatch, IID_IDispatch, DISPATCH_PROPERTYGET, DISPATCH_METHOD,
)
from aiosmb.dcerpc.v5.uuid import string_to_bin


# CLSIDs and IIDs
CLSID_MMC20 = string_to_bin('49B2791A-B1AE-4C90-9B8E-E860BA07F889')


################################################################################
# MMC20.Application wrapper class
################################################################################

class MMC20Application(IRemUnknown):
    """
    MMC20.Application COM Object wrapper.
    
    This provides access to MMC snap-in functionality including
    the ability to execute shell commands.
    
    Usage:
        mmc = MMC20Application(iInterface)
        await mmc.ExecuteShellCommand('cmd.exe', 'C:\\', '/c calc.exe', '0')
    """
    
    def __init__(self, interface):
        IRemUnknown.__init__(self, interface)
        self._iid = IID_IDispatch
        self._dispatch = IDispatch(interface)
    
    async def ExecuteShellCommand(self, command: str, directory: str = 'C:\\Windows\\System32', 
                                   parameters: str = '', windowState: str = '0'):
        """
        Execute a shell command via MMC20.Application.
        
        This method navigates through the COM object hierarchy:
            MMC20.Application -> Document -> ActiveView -> ExecuteShellCommand
        
        Args:
            command: The executable to run (e.g., 'cmd.exe')
            directory: Working directory (e.g., 'C:\\Windows\\System32')
            parameters: Command line arguments (e.g., '/c whoami')
            windowState: Window state - '0'=Minimized, '1'=Maximized, '2'=Restored
        
        Returns:
            (result_dict, error) tuple where result_dict contains:
                - 'status': 0 on success (ExecuteShellCommand is void, so no return value)
                - 'error_code': The RPC error code from the response
                - 'exception_scode': HRESULT from exception info (if any)
            
            Note: ExecuteShellCommand is a void method and does NOT return a PID.
                  The command is executed asynchronously by the MMC process.
        """
        try:
            # Step 1: Get Document property
            docDispId, err = await self._dispatch.pakIdOfName('Document')
            if err is not None:
                return None, Exception(f"Failed to get Document DISPID: {err}")
            
            docInterface, err = await self._dispatch.pakGet(docDispId)
            if err is not None:
                return None, Exception(f"Failed to get Document: {err}")
            
            # Step 2: Get ActiveView from Document
            docDispatch = IDispatch(docInterface)
            viewDispId, err = await docDispatch.pakIdOfName('ActiveView')
            if err is not None:
                return None, Exception(f"Failed to get ActiveView DISPID: {err}")
            
            viewInterface, err = await docDispatch.pakGet(viewDispId)
            if err is not None:
                return None, Exception(f"Failed to get ActiveView: {err}")
            
            # Step 3: Call ExecuteShellCommand on ActiveView
            viewDispatch = IDispatch(viewInterface)
            execDispId, err = await viewDispatch.pakIdOfName('ExecuteShellCommand')
            if err is not None:
                return None, Exception(f"Failed to get ExecuteShellCommand DISPID: {err}")
            
            resp, err = await viewDispatch.pakInvoke(
                execDispId, command, directory, parameters, windowState
            )
            if err is not None:
                return None, Exception(f"ExecuteShellCommand failed: {err}")
            
            # Extract status information from the response
            result = {
                'status': 0,  # ExecuteShellCommand is void, 0 means call succeeded
                'error_code': resp['ErrorCode'] if resp and 'ErrorCode' in resp.fields else 0,
            }
            
            # Extract exception info if available
            if resp and 'pExcepInfo' in resp.fields:
                excep_info = resp['pExcepInfo']
                result['exception_scode'] = excep_info['scode'] if 'scode' in excep_info.fields else 0
                result['exception_code'] = excep_info['wCode'] if 'wCode' in excep_info.fields else 0
            
            return result, None
            
        except Exception as e:
            return None, e
