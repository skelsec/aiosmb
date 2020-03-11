from aiosmb.dcerpc.v5.common.connection.smbdcefactory import SMBDCEFactory
from aiosmb.dcerpc.v5 import rprn
from aiosmb.dcerpc.v5.dtypes import RPC_SID
from aiosmb.wintypes.ntstatus import NTStatus
from aiosmb import logger
from aiosmb.dcerpc.v5.dtypes import NULL
from aiosmb.commons.utils.decorators import red, rr, red_gen


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

	
