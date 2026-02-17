#!/usr/bin/env python3
"""
Task Scheduler RPC Command Execution Example

Uses the Task Scheduler RPC interface (MS-TSCH) to execute commands.

Usage:
    python -m examples.rpc_taskscheduler <target> <username> <password> [domain] [command] [args]

Examples:
    # Execute calc.exe as SYSTEM (default)
    python -m examples.rpc_taskscheduler 192.168.56.11 admin password
    
    # Execute a specific command with arguments
    python -m examples.rpc_taskscheduler 192.168.56.11 admin password DOMAIN cmd.exe "/c whoami > C:\\temp\\out.txt"
    
    # Execute as a specific user (by SID) - runs on their next logon
    python -m examples.rpc_taskscheduler 192.168.56.11 admin password DOMAIN calc.exe "" --run-as S-1-5-21-xxx-1001
    
    # Execute as a specific user (by username) - resolves SID automatically  
    python -m examples.rpc_taskscheduler 192.168.56.11 admin password DOMAIN calc.exe "" --run-as targetuser

Options:
    --run-as SID|USER  Run the task as a specific user (by SID or username)
    --no-cleanup       Don't delete the task after execution (required for logon triggers)
    --task-name        Specify a custom task name
    --debug            Enable debug logging
"""

import asyncio
import sys
import logging
import uuid

from aiosmb.dcerpc.v5.connection import DCERPC5Connection
from aiosmb.dcerpc.v5.common.connection.authentication import DCERPCAuth
from aiosmb.dcerpc.v5.interfaces.endpointmgr import EPM
from aiosmb.dcerpc.v5 import tsch
from aiosmb.dcerpc.v5.dtypes import NULL
from aiosmb.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY


def generate_task_xml(command: str, arguments: str = '', run_as_sid: str = None) -> str:
    """
    Generate XML task definition for Windows Task Scheduler.
    
    Args:
        command: Executable to run
        arguments: Command arguments
        run_as_sid: If specified, task runs as this user on logon.
                    If None, runs as SYSTEM immediately.
    """
    if run_as_sid:
        # LogonTrigger - runs when the specified user logs in
        # Task runs in the user's interactive session context
        xml = f'''<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>{run_as_sid}</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{run_as_sid}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{command}</Command>
      <Arguments>{arguments}</Arguments>
    </Exec>
  </Actions>
</Task>'''
    else:
        # CalendarTrigger with SYSTEM - we run it manually
        xml = f'''<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2015-07-15T20:35:13.2757294</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="LocalSystem">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>P3D</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="LocalSystem">
    <Exec>
      <Command>{command}</Command>
      <Arguments>{arguments}</Arguments>
    </Exec>
  </Actions>
</Task>'''
    return xml


async def resolve_username_to_sid(dce_target, auth, target: str, username: str, domain: str) -> str:
    """
    Resolve a username to SID using SAMR RPC.
    
    Returns SID string like 'S-1-5-21-xxx-1001' or None on failure.
    """
    try:
        from aiosmb.dcerpc.v5 import samr
        from aiosmb.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
        
        # Connect to SAMR
        epm_target, err = await EPM.create_target(target, samr.MSRPC_UUID_SAMR)
        if err is not None:
            print(f"[!] EPM lookup failed: {err}")
            return None
        
        dce = DCERPC5Connection(auth, epm_target)
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        _, err = await dce.connect()
        if err is not None:
            print(f"[!] SAMR connect failed: {err}")
            return None
        
        _, err = await dce.bind(samr.MSRPC_UUID_SAMR)
        if err is not None:
            print(f"[!] SAMR bind failed: {err}")
            await dce.disconnect()
            return None
        
        # Connect to SAMR server
        resp, err = await samr.hSamrConnect(dce)
        if err is not None:
            print(f"[!] SamrConnect failed: {err}")
            await dce.disconnect()
            return None
        server_handle = resp['ServerHandle']
        
        # Lookup domain to get domain SID
        # Use the domain name (e.g., "NORTH" from "north.sevenkingdoms.local")
        domain_name = domain.split('.')[0].upper() if domain else 'BUILTIN'
        
        resp, err = await samr.hSamrLookupDomainInSamServer(dce, server_handle, domain_name)
        if err is not None:
            print(f"[!] LookupDomain failed for '{domain_name}': {err}")
            await dce.disconnect()
            return None
        domain_sid = resp['DomainId']
        domain_sid_str = domain_sid.formatCanonical()
        
        # Open the domain
        resp, err = await samr.hSamrOpenDomain(dce, server_handle, MAXIMUM_ALLOWED, domain_sid)
        if err is not None:
            print(f"[!] OpenDomain failed: {err}")
            await dce.disconnect()
            return None
        domain_handle = resp['DomainHandle']
        
        # Lookup the username to get RID
        resp, err = await samr.hSamrLookupNamesInDomain(dce, domain_handle, [username])
        if err is not None:
            print(f"[!] LookupNames failed for '{username}': {err}")
            await dce.disconnect()
            return None
        
        # Get the RID
        rid = resp['RelativeIds']['Element'][0]['Data']
        
        # Combine domain SID and RID
        sid = f"{domain_sid_str}-{rid}"
        
        await dce.disconnect()
        return sid
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"[!] SID resolution failed: {e}")
        return None


async def taskscheduler_exec(target: str, username: str, password: str, 
                              domain: str = '', command: str = 'calc.exe',
                              arguments: str = '', task_name: str = None,
                              cleanup: bool = True, run_as: str = None,
                              debug: bool = False):
    """
    Execute a command via Task Scheduler RPC interface.
    
    Args:
        run_as: If specified, run as this user (SID or username).
                Task will trigger on user logon.
    """
    if debug:
        logging.basicConfig(level=logging.DEBUG)
    
    print(f"[*] Connecting to {target} via RPC...")
    
    # Resolve run_as to SID if it's a username
    run_as_sid = None
    if run_as:
        if run_as.startswith('S-1-'):
            run_as_sid = run_as
            print(f"[*] Running as SID: {run_as_sid}")
        else:
            print(f"[*] Resolving username '{run_as}' to SID...")
            auth_for_lookup = DCERPCAuth.from_components(
                username=username,
                secret=password,
                domain=domain or ''
            )
            run_as_sid = await resolve_username_to_sid(None, auth_for_lookup, target, run_as, domain)
            if run_as_sid:
                print(f"[+] Resolved to SID: {run_as_sid}")
            else:
                print(f"[-] Failed to resolve username to SID")
                return False
    
    try:
        # Create auth from components
        auth = DCERPCAuth.from_components(
            username=username,
            secret=password,
            domain=domain or ''
        )
        
        # Get endpoint for Task Scheduler
        print(f"[*] Resolving Task Scheduler endpoint...")
        epm_target, err = await EPM.create_target(target, tsch.MSRPC_UUID_TSCHS)
        if err is not None:
            print(f"[-] EPM lookup failed: {err}")
            return False
        
        # Connect to Task Scheduler RPC
        dce = DCERPC5Connection(auth, epm_target)
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)  # Required for Task Scheduler
        _, err = await dce.connect()
        if err is not None:
            print(f"[-] Connect failed: {err}")
            return False
        
        _, err = await dce.bind(tsch.MSRPC_UUID_TSCHS)
        if err is not None:
            print(f"[-] Bind failed: {err}")
            return False
        
        print(f"[+] Connected to Task Scheduler RPC")
        
        # Generate task name
        if task_name is None:
            task_name = f"\\Task_{uuid.uuid4().hex[:8]}"
        elif not task_name.startswith('\\'):
            task_name = '\\' + task_name
        
        # Generate task XML
        xml = generate_task_xml(command, arguments, run_as_sid)
        
        # Register the task
        print(f"[*] Registering task: {task_name}")
        print(f"[*] Command: {command} {arguments}")
        if run_as_sid:
            print(f"[*] Task will execute when user {run_as_sid} logs in")
        
        resp, err = await tsch.hSchRpcRegisterTask(
            dce,
            task_name,
            xml,
            tsch.TASK_CREATE,
            NULL,
            tsch.TASK_LOGON_INTERACTIVE_TOKEN
        )
        if err is not None:
            print(f"[-] RegisterTask failed: {err}")
            return False
        
        print(f"[+] Task registered: {resp['pActualPath']}")
        
        # Run the task immediately (only if not using run_as with LogonTrigger)
        if not run_as_sid:
            print(f"[*] Running task...")
            run_resp, err = await tsch.hSchRpcRun(dce, task_name)
            if err is not None:
                print(f"[!] Warning: Run failed: {err}")
            else:
                print(f"[+] Task executed!")
        else:
            print(f"[+] Task will execute on next logon of target user")
            print(f"[!] Note: Task is NOT auto-deleted (use --no-cleanup or delete manually)")
            cleanup = False  # Don't delete logon tasks
        
        # Clean up
        if cleanup:
            print(f"[*] Cleaning up task...")
            _, err = await tsch.hSchRpcDelete(dce, task_name)
            if err is not None:
                print(f"[!] Warning: Delete failed: {err}")
            else:
                print(f"[+] Task deleted")
        
        await dce.disconnect()
        print(f"[*] Disconnected")
        return True
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"[-] Error: {e}")
        return False


async def main():
    debug = '--debug' in sys.argv
    no_cleanup = '--no-cleanup' in sys.argv
    
    # Extract --task-name and --run-as values if present
    task_name = None
    run_as = None
    args = []
    i = 1
    while i < len(sys.argv):
        if sys.argv[i] == '--task-name' and i + 1 < len(sys.argv):
            task_name = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == '--run-as' and i + 1 < len(sys.argv):
            run_as = sys.argv[i + 1]
            i += 2
        elif sys.argv[i].startswith('--'):
            i += 1
        else:
            args.append(sys.argv[i])
            i += 1
    
    if len(args) < 3:
        print(__doc__)
        print("\nOptions:")
        print("  --run-as SID|USER  Run task as specific user on their logon")
        print("  --no-cleanup       Don't delete the task after creation")
        print("  --task-name NAME   Specify a custom task name")
        print("  --debug            Enable debug logging")
        sys.exit(1)
    
    target = args[0]
    username = args[1]
    password = args[2]
    domain = args[3] if len(args) > 3 else ''
    command = args[4] if len(args) > 4 else 'calc.exe'
    arguments = args[5] if len(args) > 5 else ''
    
    success = await taskscheduler_exec(
        target, username, password, domain, command, arguments,
        task_name=task_name, cleanup=not no_cleanup, run_as=run_as, debug=debug
    )
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    asyncio.run(main())
