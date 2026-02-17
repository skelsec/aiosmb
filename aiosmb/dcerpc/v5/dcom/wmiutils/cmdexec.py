

async def wmi_cmd_exec(iWbemServices, command):
    """
    Execute a command using Win32_Process.Create.
    """
    try:
        result, err = await iWbemServices.GetObject('Win32_Process')
        if err is not None:
            print(f"[-] GetObject failed: {err}")
            return
        
        win32Process, _ = result
        output, err = await win32Process.Create(command, 'C:\\', None)
        if err is not None:
            raise err
        
        # Get the results
        props = output.getProperties()
        return_value = props.get('ReturnValue', {}).get('value', 'Unknown')
        process_id = props.get('ProcessId', {}).get('value', 'Unknown')
        
        return return_value, process_id, None
    except Exception as e:
        return None, None, e