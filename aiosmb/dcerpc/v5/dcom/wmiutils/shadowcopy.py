async def wmi_create_shadow_copy(iWbemServices, volume: str):
    """Create a shadow copy and return (shadow_id, device_object)"""
    result, err = await iWbemServices.GetObject('Win32_ShadowCopy')
    if err is not None:
        raise err
    
    win32ShadowCopy, _ = result
    
    try:
        output, err = await win32ShadowCopy.Create(volume, 'ClientAccessible')
        if err is not None:
            raise err
        
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
            raise Exception(f"Shadow copy creation failed: {error_msg}")
        
        # Get the device object path
        device_object = None
        if shadow_id:
            query = f"SELECT DeviceObject FROM Win32_ShadowCopy WHERE ID='{shadow_id}'"
            iEnum, err = await iWbemServices.ExecQuery(query)
            if err is not None:
                raise err
            items, _ = await iEnum.Next(0xffffffff, 1)
            if items:
                device_object = items[0].getProperties().get('DeviceObject', {}).get('value', None)
        
        return shadow_id, device_object, None

    except Exception as e:
        return None, None, e

async def wmi_delete_shadow_copy(iWbemServices, shadow_id: str) -> bool:
    """Delete a shadow copy by ID using IWbemServices.DeleteInstance"""
    try:
        object_path = f'Win32_ShadowCopy.ID="{shadow_id}"'
        result, err = await iWbemServices.DeleteInstance(object_path)
        if err is not None:
            raise err
        return True, None
    except Exception as e:
        return None, e