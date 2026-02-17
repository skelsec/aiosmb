#!/usr/bin/env python3
"""
WMI via DCE/RPC (Direct TCP) Example

This example demonstrates how to use WMI through direct DCE/RPC connections
without going through SMB. It connects directly to TCP port 135 (DCOM/EPM).

Usage:
    python wmi_via_epm.py <target> <username> <password> [domain] [--debug]
    
Example:
    python wmi_via_epm.py 192.168.1.100 administrator P@ssw0rd MYDOMAIN
    python wmi_via_epm.py 192.168.1.100 administrator P@ssw0rd MYDOMAIN --debug
"""

import asyncio
import sys
import logging

from aiosmb.dcerpc.v5.dcom.connection import DCOMConnection
from aiosmb.dcerpc.v5.common.connection.authentication import DCERPCAuth
from aiosmb.dcerpc.v5.dcom.wmi import (
    CLSID_WbemLevel1Login,
    IID_IWbemLevel1Login,
    IWbemLevel1Login,
)
from aiosmb.dcerpc.v5.dtypes import NULL


async def wmi_query_via_epm(target: str, username: str, password: str, domain: str = '', debug: bool = False):
    """
    Connect to WMI via direct DCE/RPC (port 135) and execute a query.
    
    This method connects directly to DCOM ports without using SMB.
    
    Args:
        target: Target hostname or IP address
        username: Username for authentication
        password: Password for authentication
        domain: Domain name (optional)
        debug: Enable debug logging
    """
    
    # Setup logging
    if debug:
        logging.basicConfig(level=logging.DEBUG, format='%(name)s - %(levelname)s - %(message)s')
        # Also enable aiosmb logger
        aiosmb_logger = logging.getLogger('aiosmb')
        aiosmb_logger.setLevel(logging.DEBUG)
    
    print(f"[*] Connecting to {target} via DCE/RPC (port 135)...")
    
    # Create authentication credentials
    auth = DCERPCAuth.from_components(
        username=username,
        secret=password,
        domain=domain or ''
    )
    
    # Create DCOM connection with direct TCP
    # This will connect to port 135 (RPC Endpoint Mapper / DCOM)
    dcom = DCOMConnection(
        target=target,
        auth=auth,
        domain=domain
    )
    
    try:
        # Initialize DCOM connection
        # This will:
        # 1. Connect to port 135
        # 2. Bind to IObjectExporter interface  
        # 3. Set up OXID resolution
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
            import traceback
            print(f"[-] CoCreateInstanceEx failed: {err} {traceback.format_tb(err.__traceback__)}")
            return
        
        print(f"[+] WbemLevel1Login activated")
        
        # Create IWbemLevel1Login interface wrapper
        iWbemLevel1Login = IWbemLevel1Login(iInterface)
        
        # Login to WMI namespace
        print(f"[*] Logging into WMI namespace //./root/cimv2...")
        iWbemServices, err = await iWbemLevel1Login.NTLMLogin(
            '//./root/cimv2',
            NULL,
            NULL
        )
        if err is not None:
            import traceback
            print(f"[-] NTLMLogin failed: {err} {traceback.format_tb(err.__traceback__)}")
            return
        
        print(f"[+] WMI login successful")
        
        # Release login interface
        await iWbemLevel1Login.RemRelease()
        
        # Execute WQL queries
        await run_sample_queries(iWbemServices)
        
        # Cleanup
        await iWbemServices.RemRelease()
        
    finally:
        await dcom.disconnect()
        print(f"[*] Disconnected")


async def run_sample_queries(iWbemServices):
    """Run several sample WMI queries"""
    
    # Query 1: List processes
    print(f"\n{'='*60}")
    print(f"Query: Win32_Process (top 10)")
    print(f"{'='*60}")
    
    iEnum, err = await iWbemServices.ExecQuery(
        'SELECT Name, ProcessId, WorkingSetSize FROM Win32_Process'
    )
    if err is None:
        count = 0
        while count < 10:
            items, err = await iEnum.Next(0xffffffff, 1)
            if err is not None or not items:
                break
            for item in items:
                name = getattr(item, 'Name', 'N/A')
                pid = getattr(item, 'ProcessId', 'N/A')
                mem = getattr(item, 'WorkingSetSize', 0)
                mem_mb = int(mem) / 1024 / 1024 if mem else 0
                print(f"  PID {pid}: {name} ({mem_mb:.1f} MB)")
                count += 1
        await iEnum.RemRelease()
    else:
        print(f"  Query failed: {err}")
    
    # Query 1b: Win32_NetworkAdapterConfiguration (SELECT * - complex type with arrays)
    print(f"\n{'='*60}")
    print(f"Query: Win32_NetworkAdapterConfiguration (SELECT *)")
    print(f"{'='*60}")
    
    iEnum, err = await iWbemServices.ExecQuery(
        'SELECT * FROM Win32_NetworkAdapterConfiguration'
    )
    if err is None:
        results, _ = await iEnum.FetchAll(limit=50, as_dict=True, batch_size=10)
        print(f"  Total adapters: {len(results)}")
        for r in results:
            desc = r.get('Description', 'N/A')
            ip = r.get('IPAddress', 'N/A')
            mac = r.get('MACAddress', 'N/A')
            print(f"    {desc} | MAC: {mac} | IP: {ip}")
        await iEnum.RemRelease()
    else:
        print(f"  Query failed: {err}")
    
    # Query 1c: Win32_LoggedOnUser (SELECT * - association class)
    print(f"\n{'='*60}")
    print(f"Query: Win32_LoggedOnUser (SELECT *, first 10)")
    print(f"{'='*60}")
    
    iEnum, err = await iWbemServices.ExecQuery(
        'SELECT * FROM Win32_LoggedOnUser'
    )
    if err is None:
        count = 0
        async for item in iEnum:
            antecedent = getattr(item, 'Antecedent', 'N/A')
            dependent = getattr(item, 'Dependent', 'N/A')
            print(f"  {antecedent} -> {dependent}")
            count += 1
            if count >= 10:
                print(f"  ... (showing first 10 only)")
                break
        await iEnum.RemRelease()
    else:
        print(f"  Query failed: {err}")
    
    # Query 2: System info
    print(f"\n{'='*60}")
    print(f"Query: Win32_ComputerSystem")
    print(f"{'='*60}")
    
    iEnum, err = await iWbemServices.ExecQuery(
        'SELECT Name, Domain, TotalPhysicalMemory, NumberOfProcessors FROM Win32_ComputerSystem'
    )
    if err is None:
        items, err = await iEnum.Next(0xffffffff, 1)
        if items:
            for item in items:
                print(f"  Computer Name: {getattr(item, 'Name', 'N/A')}")
                print(f"  Domain: {getattr(item, 'Domain', 'N/A')}")
                mem = getattr(item, 'TotalPhysicalMemory', 0)
                mem_gb = int(mem) / 1024 / 1024 / 1024 if mem else 0
                print(f"  Total Memory: {mem_gb:.1f} GB")
                print(f"  Processors: {getattr(item, 'NumberOfProcessors', 'N/A')}")
        await iEnum.RemRelease()
    else:
        print(f"  Query failed: {err}")
    
    # Query 3: Operating System
    print(f"\n{'='*60}")
    print(f"Query: Win32_OperatingSystem")
    print(f"{'='*60}")
    
    iEnum, err = await iWbemServices.ExecQuery(
        'SELECT Caption, Version, BuildNumber, OSArchitecture FROM Win32_OperatingSystem'
    )
    if err is None:
        items, err = await iEnum.Next(0xffffffff, 1)
        if items:
            for item in items:
                print(f"  OS: {getattr(item, 'Caption', 'N/A')}")
                print(f"  Version: {getattr(item, 'Version', 'N/A')}")
                print(f"  Build: {getattr(item, 'BuildNumber', 'N/A')}")
                print(f"  Architecture: {getattr(item, 'OSArchitecture', 'N/A')}")
        await iEnum.RemRelease()
    else:
        print(f"  Query failed: {err}")
    
    # Query 4: Network adapters
    print(f"\n{'='*60}")
    print(f"Query: Win32_NetworkAdapterConfiguration (IP enabled)")
    print(f"{'='*60}")
    
    iEnum, err = await iWbemServices.ExecQuery(
        'SELECT Description, IPAddress, MACAddress FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = True'
    )
    if err is None:
        while True:
            items, err = await iEnum.Next(0xffffffff, 1)
            if err is not None or not items:
                break
            for item in items:
                desc = getattr(item, 'Description', 'N/A')
                mac = getattr(item, 'MACAddress', 'N/A')
                ips = getattr(item, 'IPAddress', [])
                print(f"  Adapter: {desc}")
                print(f"    MAC: {mac}")
                if ips:
                    print(f"    IPs: {', '.join(ips) if isinstance(ips, list) else ips}")
        await iEnum.RemRelease()
    else:
        print(f"  Query failed: {err}")
    
    # Query 5: Services
    print(f"\n{'='*60}")
    print(f"Query: Win32_Service (Running, first 10)")
    print(f"{'='*60}")
    
    iEnum, err = await iWbemServices.ExecQuery(
        "SELECT Name, DisplayName, State FROM Win32_Service WHERE State = 'Running'"
    )
    if err is None:
        count = 0
        while count < 10:
            items, err = await iEnum.Next(0xffffffff, 1)
            if err is not None or not items:
                break
            for item in items:
                name = getattr(item, 'Name', 'N/A')
                display = getattr(item, 'DisplayName', 'N/A')
                print(f"  {name}: {display}")
                count += 1
        if count >= 10:
            print(f"  ... (showing first 10 only)")
        await iEnum.RemRelease()
    else:
        print(f"  Query failed: {err}")


async def wmi_exec_method_via_epm(target: str, username: str, password: str, 
                                   domain: str = '', command: str = 'calc.exe'):
    """
    Connect to WMI via direct DCE/RPC and execute a command using Win32_Process.Create.
    """
    
    print(f"[*] Connecting to {target} via DCE/RPC (port 135)...")
    
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
            import traceback
            print(f"[-] NTLMLogin failed: {err} {traceback.format_tb(err.__traceback__)}")
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
        
        # Debug: Print method info
        methods = win32Process.getMethods()
        create_method = methods.get('Create', {})
        print(f"[DEBUG] Create method info:")
        print(f"  InParams: {list(create_method.get('InParams', {}).keys())}")
        if 'InParamsRaw' in create_method:
            print(f"  InParamsRaw present: Yes")
        else:
            print(f"  InParamsRaw present: No")
        
        # Execute the Create method
        print(f"[*] Executing: {command}")
        
        output, err = await win32Process.Create(command, 'C:\\', None)
        if err is not None:
            print(f"[-] Create failed: {err}")
            import traceback
            traceback.print_exc()
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
        
        await iWbemServices.RemRelease()
        
    finally:
        await dcom.disconnect()
        print(f"[*] Disconnected")


async def wmi_get_class_info(target: str, username: str, password: str, domain: str = '', debug: bool = False):
    """
    Example: Get class definition and inspect methods/properties.
    """
    
    # Setup logging
    if debug:
        logging.basicConfig(level=logging.DEBUG, format='%(name)s - %(levelname)s - %(message)s')
        aiosmb_logger = logging.getLogger('aiosmb')
        aiosmb_logger.setLevel(logging.DEBUG)
    
    print(f"[*] Connecting to {target} via DCE/RPC (port 135)...")
    
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
            import traceback
            print(f"[-] NTLMLogin failed: {err} {traceback.format_tb(err.__traceback__)}")
            return
        
        await iWbemLevel1Login.RemRelease()
        
        # Get Win32_Process class definition
        print(f"\n[*] Getting Win32_Process class definition...")
        result, err = await iWbemServices.GetObject('Win32_Process')
        if err is not None:
            print(f"[-] GetObject failed: {err}")
            return
        
        win32Process, _ = result
        
        # Print class information
        print(f"\n{'='*60}")
        print(f"Class: Win32_Process")
        print(f"{'='*60}")
        
        print(f"\nProperties:")
        props = win32Process.getProperties()
        for i, (name, info) in enumerate(props.items()):
            if i >= 15:
                print(f"  ... and {len(props) - 15} more properties")
                break
            ptype = info.get('stype', 'unknown')
            print(f"  {name}: {ptype}")
        
        print(f"\nMethods:")
        methods = win32Process.getMethods()
        for name, info in methods.items():
            in_params = info.get('InParams', {})
            in_str = ', '.join(in_params.keys()) if in_params else 'void'
            print(f"  {name}({in_str})")
        
        await iWbemServices.RemRelease()
        
    finally:
        await dcom.disconnect()


async def wmi_shadowcopy_test(target: str, username: str, password: str, domain: str = '', debug: bool = False):
    """
    Test Shadow Copy operations: Create -> Verify -> Delete -> Verify deletion
    
    This tests ExecMethod and ExecQuery in a real-world scenario.
    """
    print(f"[*] Shadow Copy Test: Create -> Verify -> Delete -> Verify")
    print(f"[*] Connecting to {target}...")
    
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
        
        iInterface, err = await dcom.CoCreateInstanceEx(
            CLSID_WbemLevel1Login,
            IID_IWbemLevel1Login
        )
        if err is not None:
            print(f"[-] CoCreateInstanceEx failed: {err}")
            return False
        
        iWbemLevel1Login = IWbemLevel1Login(iInterface)
        
        iWbemServices, err = await iWbemLevel1Login.NTLMLogin(
            '//./root/cimv2',
            NULL,
            NULL
        )
        if err is not None:
            print(f"[-] NTLMLogin failed: {err}")
            return False
        
        await iWbemLevel1Login.RemRelease()
        
        # Step 1: Count existing shadow copies
        print(f"\n[1/4] Counting existing shadow copies...")
        initial_count = await count_shadow_copies(iWbemServices)
        print(f"      Found {initial_count} existing shadow copy(ies)")
        
        # Step 2: Create a new shadow copy
        print(f"\n[2/4] Creating shadow copy of C:\\...")
        shadow_id, device_object = await create_shadow_copy_test(iWbemServices, 'C:\\')
        
        if shadow_id is None:
            print(f"[-] Failed to create shadow copy")
            await iWbemServices.RemRelease()
            return False
        
        print(f"      Created: {shadow_id}")
        print(f"      Device:  {device_object}")
        
        # Step 3: Verify the shadow copy exists
        print(f"\n[3/4] Verifying shadow copy was created...")
        new_count = await count_shadow_copies(iWbemServices)
        
        if new_count == initial_count + 1:
            print(f"      ✓ Shadow copy count increased: {initial_count} -> {new_count}")
        else:
            print(f"      ✗ Unexpected count: expected {initial_count + 1}, got {new_count}")
        
        # Also verify by querying for the specific ID
        found = await verify_shadow_copy_exists(iWbemServices, shadow_id)
        if found:
            print(f"      ✓ Shadow copy {shadow_id} found in query")
        else:
            print(f"      ✗ Shadow copy {shadow_id} NOT found in query")
        
        # Step 4: Delete the shadow copy
        print(f"\n[4/4] Deleting shadow copy...")
        deleted = await delete_shadow_copy_test(iWbemServices, shadow_id)
        
        if deleted:
            print(f"      ✓ Delete method succeeded")
        else:
            print(f"      ✗ Delete method failed")
        
        # Verify deletion
        final_count = await count_shadow_copies(iWbemServices)
        if final_count == initial_count:
            print(f"      ✓ Shadow copy count restored: {new_count} -> {final_count}")
        else:
            print(f"      ✗ Unexpected final count: expected {initial_count}, got {final_count}")
        
        found_after = await verify_shadow_copy_exists(iWbemServices, shadow_id)
        if not found_after:
            print(f"      ✓ Shadow copy {shadow_id} no longer exists")
        else:
            print(f"      ✗ Shadow copy {shadow_id} still exists!")
        
        # Summary
        success = (new_count == initial_count + 1) and deleted and (final_count == initial_count)
        print(f"\n{'='*60}")
        if success:
            print(f"[+] Shadow Copy Test: PASSED")
        else:
            print(f"[-] Shadow Copy Test: FAILED")
        print(f"{'='*60}")
        
        await iWbemServices.RemRelease()
        return success
        
    finally:
        await dcom.disconnect()


async def count_shadow_copies(iWbemServices) -> int:
    """Count existing shadow copies"""
    iEnum, err = await iWbemServices.ExecQuery('SELECT ID FROM Win32_ShadowCopy')
    if err is not None:
        return 0
    
    count = 0
    while True:
        items, err = await iEnum.Next(0xffffffff, 1)
        if err is not None or not items:
            break
        count += len(items)
    
    return count


async def verify_shadow_copy_exists(iWbemServices, shadow_id: str) -> bool:
    """Check if a specific shadow copy exists"""
    query = f"SELECT ID FROM Win32_ShadowCopy WHERE ID='{shadow_id}'"
    iEnum, err = await iWbemServices.ExecQuery(query)
    if err is not None:
        return False
    
    items, _ = await iEnum.Next(0xffffffff, 1)
    return bool(items)


async def create_shadow_copy_test(iWbemServices, volume: str):
    """Create a shadow copy and return (shadow_id, device_object)"""
    result, err = await iWbemServices.GetObject('Win32_ShadowCopy')
    if err is not None:
        print(f"      GetObject failed: {err}")
        return None, None
    
    win32ShadowCopy, _ = result
    
    try:
        output, err = await win32ShadowCopy.Create(volume, 'ClientAccessible')
        if err is not None:
            print(f"      Create method failed: {err}")
            return None, None
        
        props = output.getProperties()
        return_value = props.get('ReturnValue', {}).get('value', -1)
        shadow_id = props.get('ShadowID', {}).get('value', None)
        
        if return_value != 0:
            error_codes = {
                1: "Access denied",
                2: "Invalid argument", 
                3: "Volume not found",
                4: "Volume not supported",
                5: "Unsupported context",
                6: "Insufficient storage",
                7: "Volume in use",
                8: "Max shadow copies reached",
                9: "Another operation in progress",
                10: "Provider vetoed",
                11: "Provider not registered",
                12: "Provider failure",
            }
            error_msg = error_codes.get(return_value, f"Unknown ({return_value})")
            print(f"      Create returned error: {error_msg}")
            return None, None
        
        # Get the device object path
        device_object = None
        if shadow_id:
            query = f"SELECT DeviceObject FROM Win32_ShadowCopy WHERE ID='{shadow_id}'"
            iEnum, err = await iWbemServices.ExecQuery(query)
            if err is None:
                items, _ = await iEnum.Next(0xffffffff, 1)
                if items:
                    device_object = items[0].getProperties().get('DeviceObject', {}).get('value', None)
        
        return shadow_id, device_object
        
    except Exception as e:
        print(f"      Exception: {e}")
        import traceback
        traceback.print_exc()
        return None, None


async def delete_shadow_copy_test(iWbemServices, shadow_id: str) -> bool:
    """Delete a shadow copy by ID using IWbemServices.DeleteInstance"""
    try:
        # Build the object path
        object_path = f'Win32_ShadowCopy.ID="{shadow_id}"'
        
        # Use DeleteInstance on IWbemServices (not a method on the instance)
        result, err = await iWbemServices.DeleteInstance(object_path)
        if err is not None:
            print(f"      DeleteInstance failed: {err}")
            return False
        
        return True
        
    except Exception as e:
        print(f"      Exception: {e}")
        import traceback
        traceback.print_exc()
        return False


async def main():
    # Check for --debug flag
    debug = '--debug' in sys.argv
    args = [a for a in sys.argv[1:] if a != '--debug']
    
    if len(args) < 3:
        print(__doc__)
        sys.exit(1)
    
    target = args[0]
    username = args[1]
    password = args[2]
    domain = args[3] if len(args) > 3 else ''
    
    # Run the query example
    await wmi_query_via_epm(target, username, password, domain, debug=debug)
    
    # Run the GetObject example
    print("\n" + "="*80 + "\n")
    await wmi_get_class_info(target, username, password, domain, debug=debug)
    
    # Run command execution example
    print("\n" + "="*80 + "\n")
    await wmi_exec_method_via_epm(target, username, password, domain, 'notepad.exe')
    
    # Run shadow copy test (create -> verify -> delete -> verify)
    print("\n" + "="*80 + "\n")
    await wmi_shadowcopy_test(target, username, password, domain, debug=debug)


if __name__ == '__main__':
    asyncio.run(main())
