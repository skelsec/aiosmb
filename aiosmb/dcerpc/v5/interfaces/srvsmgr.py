from aiosmb.dcerpc.v5.transport.smbtransport import SMBTransport
from aiosmb.dcerpc.v5 import srvs
from aiosmb.dcerpc.v5.dtypes import RPC_SID
from aiosmb.commons.ntstatus import NTStatus
from aiosmb import logger
from aiosmb.dcerpc.v5.dtypes import NULL
		
class SMBSRVS:
	def __init__(self, connection):
		self.connection = connection
		self.service_manager = None
		
		self.dce = None
		self.handle = None
		
		self.domain_ids = {} #sid to RPC_SID
		self.domain_handles = {} #handle to sid
		
	async def __aenter__(self):
		return self
		
	async def __aexit__(self, exc_type, exc, traceback):
		await self.close()
		
	async def connect(self, open = True):
		rpctransport = SMBTransport(self.connection, filename=r'\srvsvc')
		self.dce = rpctransport.get_dce_rpc()
		await self.dce.connect()
		await self.dce.bind(srvs.MSRPC_UUID_SRVS)
		
	async def close(self):
		if self.dce:
			try:
				await self.dce.disconnect()
			except:
				pass
			return
	
	async def list_shares(self, level = 1):
		level_name = 'Level%s' % level
		status = NTStatus.MORE_ENTRIES
		resumeHandle = 0
		while status == NTStatus.MORE_ENTRIES:
			try:
				resp = await srvs.hNetrShareEnum(self.dce, level, resumeHandle = resumeHandle)
			except Exception as e:
				print(str(e))
				if str(e).find('STATUS_MORE_ENTRIES') < 0:
					raise
				resp = e.get_packet()
			
			for entry in resp['InfoStruct']['ShareInfo'][level_name]['Buffer']:
				yield entry['shi1_netname'][:-1], entry['shi1_type'], entry['shi1_remark']
			
			resumeHandle = resp['ResumeHandle'] 
			status = NTStatus(resp['ErrorCode'])	
	
	async def list_sessions(self, level = 10):
		if level not in [1, 10]:
			raise Exception('Only levels 1 and 10 implemented!')
		level_name = 'Level%s' % level
		status = NTStatus.MORE_ENTRIES
		resumeHandle = 0
		while status == NTStatus.MORE_ENTRIES:
			try:
				resp = await srvs.hNetrSessionEnum(self.dce, '\x00', NULL, level, resumeHandle = resumeHandle)
			except Exception as e:
				print(str(e))
				if str(e).find('STATUS_MORE_ENTRIES') < 0:
					raise
				resp = e.get_packet()

			if level == 1:
				for entry in resp['InfoStruct']['SessionInfo'][level_name]['Buffer']:
					username = entry['sesi1_username'][:-1]
					ip_addr = entry['sesi1_cname'][:-1]					
					yield username, ip_addr

			elif level == 10:
				for entry in resp['InfoStruct']['SessionInfo'][level_name]['Buffer']:
					username = entry['sesi10_username'][:-1]
					ip_addr = entry['sesi10_cname'][:-1]
					
					yield username, ip_addr
			
			resumeHandle = resp['ResumeHandle'] 
			status = NTStatus(resp['ErrorCode'])	