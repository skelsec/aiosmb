from aiosmb.dcerpc.v5.common.connection.smbdcefactory import SMBDCEFactory
from aiosmb.dcerpc.v5 import srvs
from aiosmb.dcerpc.v5.dtypes import RPC_SID
from aiosmb.wintypes.ntstatus import NTStatus
from aiosmb import logger
from aiosmb.dcerpc.v5.dtypes import NULL
from aiosmb.commons.utils.decorators import red, rr, red_gen
		
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
		return True,None
	
	@red
	async def connect(self, open = True):
		rpctransport = SMBDCEFactory(self.connection, filename=r'\srvsvc')
		self.dce = rpctransport.get_dce_rpc()
		await rr(self.dce.connect())
		await rr(self.dce.bind(srvs.MSRPC_UUID_SRVS))

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
	
	@red_gen
	async def list_shares(self, level = 1):
		level_name = 'Level%s' % level
		status = NTStatus.MORE_ENTRIES
		resumeHandle = 0
		while status == NTStatus.MORE_ENTRIES:
			resp, err = await srvs.hNetrShareEnum(self.dce, level, resumeHandle = resumeHandle)
			if err is not None:
				if err.error_code != NTStatus.MORE_ENTRIES.value:
					raise err
				resp = err.get_packet()

			for entry in resp['InfoStruct']['ShareInfo'][level_name]['Buffer']:
				yield entry['shi1_netname'][:-1], entry['shi1_type'], entry['shi1_remark'], None
			
			resumeHandle = resp['ResumeHandle'] 
			status = NTStatus(resp['ErrorCode'])	
	
	
	async def list_sessions(self, level = 10):
		if level not in [1, 10]:
			raise Exception('Only levels 1 and 10 implemented!')
		level_name = 'Level%s' % level
		status = NTStatus.MORE_ENTRIES
		resumeHandle = 0
		while status == NTStatus.MORE_ENTRIES:
			resp, err = await srvs.hNetrSessionEnum(self.dce, '\x00', NULL, level, resumeHandle = resumeHandle)
			if err is not None:
				if err.error_code != NTStatus.MORE_ENTRIES.value:
					yield None, None, err
					return
				resp = err.get_packet()

			if level == 1:
				for entry in resp['InfoStruct']['SessionInfo'][level_name]['Buffer']:
					username = entry['sesi1_username'][:-1]
					ip_addr = entry['sesi1_cname'][:-1]					
					yield username, ip_addr, None

			elif level == 10:
				for entry in resp['InfoStruct']['SessionInfo'][level_name]['Buffer']:
					username = entry['sesi10_username'][:-1]
					ip_addr = entry['sesi10_cname'][:-1]
					
					yield username, ip_addr, None
			
			resumeHandle = resp['ResumeHandle'] 
			status = NTStatus(resp['ErrorCode'])