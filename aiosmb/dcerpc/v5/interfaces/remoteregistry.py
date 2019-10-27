
from aiosmb.dcerpc.v5.common.connection.smbdcefactory import SMBDCEFactory
from aiosmb.dcerpc.v5 import rrp
from aiosmb.dcerpc.v5.interfaces.servicemanager import *
from aiosmb.commons.utils.decorators import red, rr
		
class RRP:
	def __init__(self, connection):
		self.connection = connection
		self.service_manager = None
		
		self.dce = None
		self.handle = None
		
		self.hive_handles = {}
		
	async def __aenter__(self):
		return self
		
	async def __aexit__(self, exc_type, exc, traceback):
		await self.close()
		return True,None
	
	@red
	async def connect(self, open = False):
		rpctransport = SMBDCEFactory(self.connection,  filename=r'\winreg')
		self.dce = rpctransport.get_dce_rpc()
		await rr(self.dce.connect())
		await rr(self.dce.bind(rrp.MSRPC_UUID_RRP))
	
		if open == True:
			await rr(self.open())

		return True, None
				
	@red
	async def open(self):
		if not self.dce:
			await rr(self.connect())
		
		ans, _ = await rr(rrp.hOpenLocalMachine(self.dce))
		self.handle = ans['phKey']

		return True, None
	
	@red
	async def close(self):
		if self.dce:
			if self.handle:
				for hive_name in self.hive_handles:
					try:
						await rrp.hBaseRegCloseKey(self.dce, self.hive_handles[hive_name])
					except Exception as e:
						print(e)
						pass
			
				try:
					await rrp.hBaseRegCloseKey(self.dce, self.handle)
				except Exception as e:
					print(e)
					pass
			try:
				await self.dce.disconnect()
			except Exception as e:
				print(e)
				pass
				
		if self.service_manager:
			try:
				await self.service_manager.close()
			except Exception as e:
				print(e)
				pass
				
		return True, None
			
	#@red
	#async def enable(self):
	#	self.service_manager = ServieManager(self.connection)
		
	@red
	async def open_hive(self, hive_name):
		if not self.handle:
			await self.open()
		if hive_name in self.hive_handles:
			return
			
		ans, _ = await rr(rrp.hBaseRegCreateKey(self.dce, self.handle, hive_name))
			
		self.hive_handles[hive_name] = ans['phkResult']

		return True, None
	
	@red
	async def save_hive(self, hive_name, remote_path):
		"""
		Dumps the registry five to a file !ON THE REMOTE MACHINE!
		"""
		if not self.handle:
			await rr(self.open())
		if hive_name not in self.hive_handles:
			await rr(self.open_hive(hive_name))
			
		await rr(rrp.hBaseRegSaveKey(self.dce, self.hive_handles[hive_name], remote_path))

		return True, None
	
	@red
	async def close_hive(self, hive_name):
		if not self.handle:
			await rr(self.open())
		if hive_name not in self.hive_handles:
			await rr(self.open_hive(hive_name))
		
		await rr(rrp.hBaseRegCloseKey(self.dce, self.hive_handles[hive_name]))

		return True, None