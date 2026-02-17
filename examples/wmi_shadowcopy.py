#!/usr/bin/env python3
"""
WMI Shadow Copy Example

Uses Win32_ShadowCopy to create and manage Volume Shadow Copies (VSS).
Useful for:
  - Backup and recovery operations
  - Accessing previous versions of files
  - Recovering accidentally deleted files
  - Accessing files locked by running applications

Usage:
    python -m examples.wmi_shadowcopy <target> <username> <password> [domain] [--create C:] [--list] [--delete <id>]

Examples:
    # List existing shadow copies
    python -m examples.wmi_shadowcopy 192.168.1.100 admin password --list
    
    # Create a shadow copy of C:
    python -m examples.wmi_shadowcopy 192.168.1.100 admin password --create C:
    
    # Delete a shadow copy by ID
    python -m examples.wmi_shadowcopy 192.168.1.100 admin password --delete {GUID}

Note: After creating a shadow copy, you can access previous file versions via:
    DeviceObject path + relative file path
    e.g., \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Users\\docs\\report.docx
"""

import asyncio
import sys
import logging

from aiosmb.dcerpc.v5.dcom.connection import DCOMConnection, DCERPCAuth
from aiosmb.dcerpc.v5.dcom.wmi import (
    IWbemLevel1Login, IWbemServices,
    CLSID_WbemLevel1Login, IID_IWbemLevel1Login,
)
from aiosmb.dcerpc.v5.dtypes import NULL


async def list_shadow_copies(iWbemServices: IWbemServices):
    """List all existing shadow copies"""
    print("\n[*] Querying existing shadow copies...")
    
    iEnum, err = await iWbemServices.ExecQuery('SELECT * FROM Win32_ShadowCopy')
    if err is not None:
        print(f"[-] Query failed: {err}")
        return []
    
    shadow_copies = []
    while True:
        items, err = await iEnum.Next(0xffffffff, 1)
        if err is not None:
            if 'WBEM_S_FALSE' not in str(err) and 'S_FALSE' not in str(err):
                print(f"[-] Error during enumeration: {err}")
            break
        
        if not items:
            break
        
        for item in items:
            props = item.getProperties()
            shadow_copy = {
                'ID': props.get('ID', {}).get('value', 'N/A'),
                'DeviceObject': props.get('DeviceObject', {}).get('value', 'N/A'),
                'VolumeName': props.get('VolumeName', {}).get('value', 'N/A'),
                'InstallDate': props.get('InstallDate', {}).get('value', 'N/A'),
                'State': props.get('State', {}).get('value', 'N/A'),
            }
            shadow_copies.append(shadow_copy)
    
    if shadow_copies:
        print(f"\n[+] Found {len(shadow_copies)} shadow copy(ies):\n")
        for i, sc in enumerate(shadow_copies):
            print(f"  Shadow Copy #{i+1}")
            print(f"    ID:           {sc['ID']}")
            print(f"    DeviceObject: {sc['DeviceObject']}")
            print(f"    VolumeName:   {sc['VolumeName']}")
            print(f"    InstallDate:  {sc['InstallDate']}")
            print(f"    State:        {sc['State']}")
            print()
    else:
        print("[-] No shadow copies found")
    
    return shadow_copies


async def create_shadow_copy(iWbemServices: IWbemServices, volume: str):
    """
    Create a new shadow copy of the specified volume.
    
    Args:
        volume: Volume to snapshot (e.g., "C:" or "C:\\")
    
    Returns:
        The shadow copy ID and device path if successful
    """
    # Ensure volume format is correct (C:\)
    if not volume.endswith('\\'):
        volume = volume + '\\'
    
    print(f"\n[*] Creating shadow copy of {volume}...")
    
    # Get the Win32_ShadowCopy class for the Create method
    result, err = await iWbemServices.GetObject('Win32_ShadowCopy')
    if err is not None:
        print(f"[-] GetObject failed: {err}")
        return None, None
    
    win32ShadowCopy, _ = result
    
    # Call the Create method
    # Win32_ShadowCopy.Create(Volume, Context) returns ShadowID
    # Context can be "ClientAccessible" for VSS_CTX_CLIENT_ACCESSIBLE
    try:
        output, err = await win32ShadowCopy.Create(volume, 'ClientAccessible')
        if err is not None:
            print(f"[-] Create failed: {err}")
            return None, None
        
        props = output.getProperties()
        return_value = props.get('ReturnValue', {}).get('value', -1)
        shadow_id = props.get('ShadowID', {}).get('value', None)
        
        if return_value == 0:
            print(f"[+] Shadow copy created successfully!")
            print(f"    ShadowID: {shadow_id}")
            
            # Query to get the DeviceObject path
            if shadow_id:
                query = f"SELECT * FROM Win32_ShadowCopy WHERE ID='{shadow_id}'"
                iEnum, err = await iWbemServices.ExecQuery(query)
                if err is None:
                    items, _ = await iEnum.Next(0xffffffff, 1)
                    if items:
                        device_obj = items[0].getProperties().get('DeviceObject', {}).get('value', 'N/A')
                        print(f"    DeviceObject: {device_obj}")
                        print(f"\n[*] You can now access files via:")
                        print(f"    {device_obj}\\Windows\\System32\\config\\SAM")
                        print(f"    {device_obj}\\Windows\\System32\\config\\SYSTEM")
                        print(f"    {device_obj}\\Windows\\NTDS\\ntds.dit (on DCs)")
                        return shadow_id, device_obj
            
            return shadow_id, None
        else:
            error_codes = {
                1: "Access denied",
                2: "Invalid argument",
                3: "Specified volume not found",
                4: "Specified volume not supported",
                5: "Unsupported shadow copy context",
                6: "Insufficient storage",
                7: "Volume is in use",
                8: "Maximum number of shadow copies reached",
                9: "Another shadow copy operation is in progress",
                10: "Shadow copy provider vetoed the operation",
                11: "Shadow copy provider not registered",
                12: "Shadow copy provider failure",
            }
            error_msg = error_codes.get(return_value, f"Unknown error ({return_value})")
            print(f"[-] Failed to create shadow copy: {error_msg}")
            return None, None
            
    except Exception as e:
        print(f"[-] Exception during Create: {e}")
        import traceback
        traceback.print_exc()
        return None, None


async def delete_shadow_copy(iWbemServices: IWbemServices, shadow_id: str):
    """
    Delete a shadow copy by its ID.
    
    Args:
        shadow_id: The shadow copy ID (GUID format)
    """
    print(f"\n[*] Deleting shadow copy {shadow_id}...")
    
    # Query for the specific shadow copy
    query = f"SELECT * FROM Win32_ShadowCopy WHERE ID='{shadow_id}'"
    iEnum, err = await iWbemServices.ExecQuery(query)
    if err is not None:
        print(f"[-] Query failed: {err}")
        return False
    
    items, err = await iEnum.Next(0xffffffff, 1)
    if err is not None or not items:
        print(f"[-] Shadow copy not found: {shadow_id}")
        return False
    
    shadowCopy = items[0]
    
    # Call the Delete method on the instance
    try:
        # For instance methods, we need to use the object path
        # Win32_ShadowCopy.ID="..."
        object_path = f"Win32_ShadowCopy.ID=\"{shadow_id}\""
        
        result, err = await iWbemServices.GetObject(object_path)
        if err is not None:
            print(f"[-] GetObject failed: {err}")
            return False
        
        shadowCopyInstance, _ = result
        
        # Try to call Delete() method
        # Note: Delete is a method on the instance
        output, err = await shadowCopyInstance.Delete()
        if err is not None:
            print(f"[-] Delete failed: {err}")
            return False
        
        print(f"[+] Shadow copy deleted successfully!")
        return True
        
    except Exception as e:
        print(f"[-] Exception during Delete: {e}")
        import traceback
        traceback.print_exc()
        return False


async def main():
    if len(sys.argv) < 4:
        print(__doc__)
        sys.exit(1)
    
    target = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3]
    
    # Parse remaining args
    domain = ''
    action = 'list'
    action_arg = None
    
    i = 4
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == '--list':
            action = 'list'
        elif arg == '--create':
            action = 'create'
            if i + 1 < len(sys.argv):
                i += 1
                action_arg = sys.argv[i]
            else:
                print("[-] --create requires a volume argument (e.g., C:)")
                sys.exit(1)
        elif arg == '--delete':
            action = 'delete'
            if i + 1 < len(sys.argv):
                i += 1
                action_arg = sys.argv[i]
            else:
                print("[-] --delete requires a shadow ID argument")
                sys.exit(1)
        elif arg == '--debug':
            logging.basicConfig(level=logging.DEBUG)
        elif not arg.startswith('--'):
            domain = arg
        i += 1
    
    print(f"[*] Connecting to {target} via DCE/RPC...")
    
    auth = DCERPCAuth.from_components(
        username=username,
        secret=password,
        domain=domain or ''
    )
    
    dcom = DCOMConnection(target=target, auth=auth, domain=domain)
    
    try:
        _, err = await dcom.connect()
        if err is not None:
            import traceback
            print(f"[-] DCOM connect failed: {err}")
            if hasattr(err, '__traceback__') and err.__traceback__:
                traceback.print_tb(err.__traceback__)
            return
        
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
        
        # Perform the requested action
        if action == 'list':
            await list_shadow_copies(iWbemServices)
        
        elif action == 'create':
            if action_arg:
                await create_shadow_copy(iWbemServices, action_arg)
            else:
                print("[-] Please specify a volume (e.g., --create C:)")
        
        elif action == 'delete':
            if action_arg:
                await delete_shadow_copy(iWbemServices, action_arg)
            else:
                print("[-] Please specify a shadow copy ID (e.g., --delete {GUID})")
        
        await iWbemServices.RemRelease()
        
    finally:
        await dcom.disconnect()
        print(f"\n[*] Disconnected")


if __name__ == '__main__':
    asyncio.run(main())
