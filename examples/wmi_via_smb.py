#!/usr/bin/env python3
"""
WMI via SMB Connection Example

This example demonstrates how to use WMI through an SMB connection.
The DCOM/WMI traffic uses TCP port 135 but credentials are derived from SMB.

Usage:
    python wmi_via_smb.py <target> <username> <password> [domain]
    
Example:
    python wmi_via_smb.py 192.168.1.100 administrator P@ssw0rd MYDOMAIN
"""

import asyncio
import sys

from aiosmb.commons.connection.factory import SMBConnectionFactory
from aiosmb.dcerpc.v5.dcom.connection import DCOMConnection
from aiosmb.dcerpc.v5.dcom.wmi import (
    CLSID_WbemLevel1Login,
    IID_IWbemLevel1Login,
    IWbemLevel1Login,
)
from aiosmb.dcerpc.v5.dtypes import NULL


async def wmi_query_via_smb(target: str, username: str, password: str, domain: str = ''):
    """
    Connect to WMI via SMB and execute a query.
    
    Args:
        target: Target hostname or IP address
        username: Username for authentication
        password: Password for authentication
        domain: Domain name (optional)
    """
    
    # Build SMB connection URL
    # Format: smb2+ntlm-password://DOMAIN\username:password@target
    if domain:
        smb_url = f'smb2+ntlm-password://{domain}\\{username}:{password}@{target}'
    else:
        smb_url = f'smb2+ntlm-password://{username}:{password}@{target}'
    
    print(f"[*] Connecting to {target} via SMB...")
    
    # Create SMB connection factory and connect
    factory = SMBConnectionFactory.from_url(smb_url)
    connection = factory.get_connection()
    
    _, err = await connection.login()
    if err is not None:
        print(f"[-] SMB login failed: {err}")
        return
    
    print(f"[+] SMB connection established")
    
    # Create DCOM connection from the SMB connection
    # This extracts credentials from the SMB session
    dcom = DCOMConnection.from_smbconnection(connection)
    
    try:
        # Initialize DCOM (connects to port 135)
        _, err = await dcom.connect()
        if err is not None:
            print(f"[-] DCOM connect failed: {err}")
            return
        
        print(f"[+] DCOM connection established")
        
        # Activate WbemLevel1Login COM object
        print(f"[*] Activating WbemLevel1Login...")
        iInterface, err = await dcom.CoCreateInstanceEx(
            CLSID_WbemLevel1Login,
            IID_IWbemLevel1Login
        )
        if err is not None:
            print(f"[-] CoCreateInstanceEx failed: {err}")
            return
        
        print(f"[+] WbemLevel1Login activated")
        
        # Create IWbemLevel1Login interface
        iWbemLevel1Login = IWbemLevel1Login(iInterface)
        
        # Login to WMI namespace (root/cimv2 is the standard namespace)
        print(f"[*] Logging into WMI namespace //./root/cimv2...")
        iWbemServices, err = await iWbemLevel1Login.NTLMLogin(
            '//./root/cimv2',  # Namespace path
            NULL,               # Preferred locale
            NULL                # Context
        )
        if err is not None:
            print(f"[-] NTLMLogin failed: {err}")
            return
        
        print(f"[+] WMI login successful")
        
        # Release the login interface (no longer needed)
        await iWbemLevel1Login.RemRelease()
        
        # Execute a WQL query
        query = 'SELECT Name, ProcessId, CommandLine FROM Win32_Process'
        print(f"[*] Executing query: {query}")
        
        iEnum, err = await iWbemServices.ExecQuery(query)
        if err is not None:
            print(f"[-] ExecQuery failed: {err}")
            return
        
        print(f"[+] Query executed, enumerating results...\n")
        
        # Iterate through results
        print(f"{'PID':<8} {'Name':<30} {'CommandLine'}")
        print("-" * 80)
        
        while True:
            items, err = await iEnum.Next(0xffffffff, 1)
            if err is not None:
                # Check if it's just end of enumeration (S_FALSE)
                if 'S_FALSE' in str(err):
                    break
                print(f"[-] Next failed: {err}")
                break
            
            if not items:
                break
            
            for item in items:
                pid = getattr(item, 'ProcessId', 'N/A')
                name = getattr(item, 'Name', 'N/A')
                cmdline = getattr(item, 'CommandLine', '')
                if cmdline and len(cmdline) > 40:
                    cmdline = cmdline[:40] + '...'
                print(f"{pid:<8} {name:<30} {cmdline}")
        
        print("\n[+] Query complete")
        
        # Cleanup
        await iEnum.RemRelease()
        await iWbemServices.RemRelease()
        
    finally:
        # Disconnect DCOM
        await dcom.disconnect()
        print(f"[*] Disconnected")


async def wmi_exec_method_via_smb(target: str, username: str, password: str, 
                                  domain: str = '', command: str = 'calc.exe'):
    """
    Connect to WMI via SMB and execute a command using Win32_Process.Create.
    """
    
    if domain:
        smb_url = f'smb2+ntlm-password://{domain}\\{username}:{password}@{target}'
    else:
        smb_url = f'smb2+ntlm-password://{username}:{password}@{target}'
    
    print(f"[*] Connecting to {target} via SMB...")
    
    factory = SMBConnectionFactory.from_url(smb_url)
    connection = factory.get_connection()
    
    _, err = await connection.login()
    if err is not None:
        print(f"[-] SMB login failed: {err}")
        return
    
    print(f"[+] SMB connection established")
    
    dcom = DCOMConnection.from_smbconnection(connection)
    
    try:
        _, err = await dcom.connect()
        if err is not None:
            print(f"[-] DCOM connect failed: {err}")
            return
        
        # Activate WMI
        iInterface, err = await dcom.CoCreateInstanceEx(
            CLSID_WbemLevel1Login,
            IID_IWbemLevel1Login
        )
        if err is not None:
            print(f"[-] CoCreateInstanceEx failed: {err}")
            return
        
        iWbemLevel1Login = IWbemLevel1Login(iInterface)
        
        iWbemServices, err = await iWbemLevel1Login.NTLMLogin(
            '//./root/cimv2',
            NULL,
            NULL
        )
        if err is not None:
            print(f"[-] NTLMLogin failed: {err}")
            return
        
        await iWbemLevel1Login.RemRelease()
        
        # Get Win32_Process class
        print(f"[*] Getting Win32_Process class...")
        result, err = await iWbemServices.GetObject('Win32_Process')
        if err is not None:
            print(f"[-] GetObject failed: {err}")
            return
        
        win32Process, _ = result
        print(f"[+] Got Win32_Process class")
        
        # Execute the Create method
        print(f"[*] Executing: {command}")
        
        # The Create method takes: CommandLine, CurrentDirectory, ProcessStartupInformation
        output, err = await win32Process.Create(command, 'C:\\', None)
        if err is not None:
            print(f"[-] Create failed: {err}")
            return
        
        # Get the results
        props = output.getProperties()
        return_value = props.get('ReturnValue', {}).get('value', 'Unknown')
        process_id = props.get('ProcessId', {}).get('value', 'Unknown')
        
        if return_value == 0:
            print(f"[+] Process created successfully!")
            print(f"    PID: {process_id}")
        else:
            print(f"[-] Process creation failed with return value: {return_value}")
        
        # Cleanup
        await iWbemServices.RemRelease()
        
    finally:
        await dcom.disconnect()
        print(f"[*] Disconnected")


async def main():
    if len(sys.argv) < 4:
        print(__doc__)
        sys.exit(1)
    
    target = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3]
    domain = sys.argv[4] if len(sys.argv) > 4 else ''
    
    # Run the query example
    await wmi_query_via_smb(target, username, password, domain)
    
    # Uncomment below to also run command execution example:
    # print("\n" + "="*80 + "\n")
    # await wmi_exec_method_via_smb(target, username, password, domain, 'notepad.exe')


if __name__ == '__main__':
    asyncio.run(main())
