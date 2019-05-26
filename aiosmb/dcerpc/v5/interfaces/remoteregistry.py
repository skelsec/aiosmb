
from aiosmb.dcerpc.v5.transport.smbtransport import SMBTransport
from aiosmb.dcerpc.v5 import rrp
from aiosmb.dcerpc.v5.interfaces.servicemanager import *
		
class SMBRemoteRegistryService:
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
		
	async def connect(self, open = False):
		for i in range(2):
			try:
				rpctransport = SMBTransport(self.connection, filename=r'\winreg')
				self.dce = rpctransport.get_dce_rpc()
				await self.dce.connect()
				await self.dce.bind(rrp.MSRPC_UUID_RRP)
			
				if open == True:
					await self.open()
			except Exception as e:
				print(e)
				
	
	async def open(self):
		if not self.dce:
			await self.connect()
		
		ans = await rrp.hOpenLocalMachine(self.dce)
		self.handle = ans['phKey']
		
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
			
	
	async def enable(self):
		self.service_manager = ServieManager(self.connection)
		
		
	async def open_hive(self, hive_name):
		if not self.handle:
			await self.open()
		if hive_name in self.hive_handles:
			return
			
		try:
			ans = await rrp.hBaseRegCreateKey(self.dce, self.handle, hive_name)
		except:
			raise Exception("Can't open %s hive" % hive_name)
			
		self.hive_handles[hive_name] = ans['phkResult']
			
	async def save_hive(self, hive_name, remote_path):
		"""
		Dumps the registry five to a file !ON THE REMOTE MACHINE!
		"""
		if not self.handle:
			await self.open()
		if hive_name not in self.hive_handles:
			await self.open_hive(hive_name)
			
		await rrp.hBaseRegSaveKey(self.dce, self.hive_handles[hive_name], remote_path)
		
	async def close_hive(self, hive_name):
		if not self.handle:
			await self.open()
		if hive_name not in self.hive_handles:
			await self.open_hive(hive_name)
		
		await rrp.hBaseRegCloseKey(self.dce, self.hive_handles[hive_name])