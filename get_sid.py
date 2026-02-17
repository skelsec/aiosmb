import asyncio
from aiosmb.dcerpc.v5.dcom.connection import DCOMConnection, DCERPCAuth
from aiosmb.dcerpc.v5.dcom.wmi import IWbemServices, CLSID_WbemLevel1Login, IID_IWbemLevel1Login

async def main():
    auth = DCERPCAuth.from_components(username='vagrant', secret='vagrant', domain='north.sevenkingdoms.local')
    dcom = DCOMConnection(target='192.168.56.11', auth=auth, domain='north.sevenkingdoms.local')
    _, err = await dcom.connect()
    if err: return print(f'Error: {err}')
    
    # Create WMI connection
    iInterface, err = await dcom.CoCreateInstanceEx(CLSID_WbemLevel1Login, IID_IWbemLevel1Login)
    if err: return print(f'Error: {err}')
    
    from aiosmb.dcerpc.v5.dcom.wmi import IWbemLevel1Login
    iWbemLevel1Login = IWbemLevel1Login(iInterface)
    iWbemServices, err = await iWbemLevel1Login.NTLMLogin('//./root/cimv2')
    if err: return print(f'Error: {err}')
    
    wmi = IWbemServices(iWbemServices)
    
    # Query only domain accounts to reduce output
    enum_result, err = await wmi.ExecQuery("SELECT Name, SID, Domain FROM Win32_UserAccount WHERE Domain = 'NORTH'")
    if err: return print(f'Error: {err}')
    
    # Iterate using Next
    while True:
        objects, err = await enum_result.Next(10, timeout=5)
        if err: 
            print(f'Next error: {err}')
            break
        if not objects:
            break
        for obj in objects:
            props = obj.getProperties()
            name = props.get('Name', {}).get('value', 'N/A')
            sid = props.get('SID', {}).get('value', 'N/A')
            domain = props.get('Domain', {}).get('value', 'N/A')
            print(f"Name: {name}, SID: {sid}, Domain: {domain}")
    
    await dcom.disconnect()

asyncio.run(main())
