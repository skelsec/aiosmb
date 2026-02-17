#!/usr/bin/env python3
"""
MMC20.Application DCOM Command Execution Example

Uses MMC20.Application COM object to execute commands via DCOM.
This is an alternative to WMI for remote command execution.

Usage:
    python -m examples.dcom_mmc20 <target> <username> <password> [domain] [command]

Examples:
    # Execute calc.exe (default)
    python -m examples.dcom_mmc20 192.168.1.100 admin password DOMAIN
    
    # Execute a specific command
    python -m examples.dcom_mmc20 192.168.1.100 admin password DOMAIN "notepad.exe"
    
    # Execute cmd with arguments
    python -m examples.dcom_mmc20 192.168.1.100 admin password DOMAIN "cmd.exe /c whoami > c:\\temp\\out.txt"

Note: The command runs in the context of the authenticated user on the remote system.
"""

import asyncio
import sys
import logging

from aiosmb.dcerpc.v5.dcom.connection import DCOMConnection, DCERPCAuth
from aiosmb.dcerpc.v5.dcom.mmc import MMC20Application, CLSID_MMC20
from aiosmb.dcerpc.v5.dcom.oaut import IID_IDispatch


async def mmc20_exec(target: str, username: str, password: str, 
                     domain: str = '', command: str = 'calc.exe', debug: bool = False):
    """
    Execute a command via MMC20.Application DCOM object.
    
    Args:
        target: Target hostname or IP address
        username: Username for authentication
        password: Password for authentication
        domain: Domain name (optional)
        command: Command to execute (can include arguments)
        debug: Enable debug logging
    """
    if debug:
        logging.basicConfig(level=logging.DEBUG)
    
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
        
        # Activate MMC20.Application
        print(f"[*] Activating MMC20.Application ({CLSID_MMC20.hex()})...")
        iInterface, err = await dcom.CoCreateInstanceEx(
            CLSID_MMC20,
            IID_IDispatch
        )
        if err is not None:
            print(f"[-] CoCreateInstanceEx failed: {err}")
            return False
        
        print(f"[+] MMC20.Application activated")
        
        # Create wrapper
        mmc = MMC20Application(iInterface)
        
        # Parse command and arguments
        parts = command.split(' ', 1)
        exe = parts[0]
        args = parts[1] if len(parts) > 1 else ''
        
        # Execute command
        print(f"[*] Executing: {exe} {args}")
        result, err = await mmc.ExecuteShellCommand(
            command=exe,
            directory='C:\\Windows\\System32',
            parameters=args,
            windowState='0'  # Minimized
        )
        
        if err is not None:
            print(f"[-] ExecuteShellCommand failed: {err}")
            return False
        
        print(f"[+] Command executed successfully!")
        return True
        
    finally:
        await dcom.disconnect()
        print(f"[*] Disconnected")


async def main():
    debug = '--debug' in sys.argv
    args = [a for a in sys.argv[1:] if a != '--debug']
    
    if len(args) < 3:
        print(__doc__)
        sys.exit(1)
    
    target = args[0]
    username = args[1]
    password = args[2]
    domain = args[3] if len(args) > 3 else ''
    command = args[4] if len(args) > 4 else 'calc.exe'
    
    success = await mmc20_exec(target, username, password, domain, command, debug)
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    asyncio.run(main())
