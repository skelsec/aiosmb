from aiosmb.dcerpc.v5.transport.smbtransport import SMBTransport
from aiosmb.dcerpc.v5 import samr
from aiosmb.dcerpc.v5.dtypes import RPC_SID
from aiosmb.commons.ntstatus import NTStatus
from aiosmb import logger
		
class SMBSAMR:
	def __init__(self, connection):
		self.connection = connection
		self.service_manager = None
		
		self.dce = None
		self.handle = None
		
		self.domain_ids = {} #sid to RPC_SID
		
	async def __aenter__(self):
		return self
		
	async def __aexit__(self, exc_type, exc, traceback):
		await self.close()
		
	async def connect(self, open = True):
		for i in range(2):
			try:
				rpctransport = SMBTransport(self.connection, filename=r'\samr')
				self.dce = rpctransport.get_dce_rpc()
				await self.dce.connect()
				await self.dce.bind(samr.MSRPC_UUID_SAMR)
			
				if open == True:
					await self.open()
			except Exception as e:
				print(e)
				
	
	async def open(self):
		if not self.dce:
			await self.connect()
		
		ans = await samr.hSamrConnect(self.dce)
		self.handle = ans['ServerHandle']
		
	async def list_domains(self):
		resp = await samr.hSamrEnumerateDomainsInSamServer(self.dce, self.handle)
		domains = []
		for domain in resp['Buffer']['Buffer']:
			domains.append(domain['Name'])
		return domains
		
	async def get_domain_sid(self, domain_name):
		resp = await samr.hSamrLookupDomainInSamServer(self.dce, self.handle, domain_name)
		self.domain_ids[resp['DomainId'].formatCanonical()] = resp['DomainId']
		return resp['DomainId'].formatCanonical()
		
	async def open_domain(self, domain_sid):
		##domain_id = RPC_SID()
		##domain_id.fromCanonical(domain_sid)
		##input(domain_id.dump())
		##input(domain_id.Data)
		resp = await samr.hSamrOpenDomain(self.dce, self.handle, domainId = self.domain_ids[domain_sid])
		return resp['DomainHandle']
		
	async def list_domain_users(self, domain_handle):
		user_type = samr.USER_NORMAL_ACCOUNT
		status = NTStatus.MORE_ENTRIES
		enumerationContext = 0
		while status == NTStatus.MORE_ENTRIES:
			try:
				resp = await samr.hSamrEnumerateUsersInDomain(self.dce, domain_handle, user_type, enumerationContext=enumerationContext)
			except DCERPCException as e:
				if str(e).find('STATUS_MORE_ENTRIES') < 0:
					raise
				resp = e.get_packet()

			for user in resp['Buffer']['Buffer']:
				print(user.dump())
				yield user['Name']
				logger.debug('Machine name - rid: %s - %d'% (user['Name'], user['RelativeId']))

			enumerationContext = resp['EnumerationContext'] 
			status = NTStatus(resp['ErrorCode'])
			
	async def list_domain_groups(self, domain_handle):
		status = NTStatus.MORE_ENTRIES
		enumerationContext = 0
		while status == NTStatus.MORE_ENTRIES:
			try:
				resp = await samr.hSamrEnumerateGroupsInDomain(self.dce, domain_handle, enumerationContext=enumerationContext)
			except DCERPCException as e:
				print(str(e))
				if str(e).find('STATUS_MORE_ENTRIES') < 0:
					raise
				resp = e.get_packet()

			for group in resp['Buffer']['Buffer']:
				print(group.dump())
				yield group['Name']
			enumerationContext = resp['EnumerationContext'] 
			status = NTStatus(resp['ErrorCode'])
		