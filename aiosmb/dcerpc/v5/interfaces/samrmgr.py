from aiosmb.dcerpc.v5.transport.smbtransport import SMBTransport
from aiosmb.dcerpc.v5 import samr
from aiosmb.dcerpc.v5.dtypes import RPC_SID, DACL_SECURITY_INFORMATION
from aiosmb.commons.ntstatus import NTStatus
from aiosmb.dcerpc.v5.rpcrt import DCERPCException
from aiosmb import logger
		
class SMBSAMR:
	def __init__(self, connection):
		self.connection = connection
		self.service_manager = None
		
		self.dce = None
		self.handle = None
		
		self.domain_ids = {} #sid to RPC_SID
		self.domain_handles = {} #handle to sid
		
		self.user_handles = {} #handle to domain-sid
		self.alias_handles = {} #handle to domain-sid
		
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
		
	async def close(self):
		if self.dce:
			for dhandle in self.domain_handles:
				try:
					await self.close_handle(dhandle)
				except:
					pass
					
			for uhandle in self.user_handles:
				try:
					await self.close_handle(uhandle)
				except:
					pass
			
			try:
				await self.close_handle(self.handle)
			except:
				pass
				
			try:
				await self.dce.disconnect()
			except:
				pass
			return
			
	async def close_handle(self,handle):
		resp = await hSamrCloseHandle(handle)
		
	async def get_info(self, domain_handle, domainInformationClass = samr.DOMAIN_INFORMATION_CLASS.DomainGeneralInformation2):
		resp = await samr.hSamrQueryInformationDomain(self.dce, domain_handle, domainInformationClass = domainInformationClass)
		return resp
		
	async def list_domains(self):
		status = NTStatus.MORE_ENTRIES
		enumerationContext = 0
		while status == NTStatus.MORE_ENTRIES:
			try:
				resp = await samr.hSamrEnumerateDomainsInSamServer(self.dce, self.handle, enumerationContext = enumerationContext)
			except DCERPCException as e:
				if str(e).find('STATUS_MORE_ENTRIES') < 0:
					raise
				resp = e.get_packet()
			
			for domain in resp['Buffer']['Buffer']:
				yield domain['Name']
			
			enumerationContext = resp['EnumerationContext']
			status = NTStatus(resp['ErrorCode'])
		
	async def get_domain_sid(self, domain_name):
		resp = await samr.hSamrLookupDomainInSamServer(self.dce, self.handle, domain_name)
		self.domain_ids[resp['DomainId'].formatCanonical()] = resp['DomainId']
		return resp['DomainId'].formatCanonical()
		
	async def open_domain(self, domain_sid, access_level = samr.MAXIMUM_ALLOWED):
		resp = await samr.hSamrOpenDomain(self.dce, self.handle, domainId = self.domain_ids[domain_sid], desiredAccess = access_level)
		self.domain_handles[resp['DomainHandle']] = domain_sid
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
				user_sid = '%s-%s' % (self.domain_handles[domain_handle], user['RelativeId'])
				yield user['Name'], user_sid 

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
				group_sid = '%s-%s' % (self.domain_handles[domain_handle], group['RelativeId'])
				yield group['Name'], group_sid
			enumerationContext = resp['EnumerationContext'] 
			status = NTStatus(resp['ErrorCode'])
			
			
	async def enumerate_users(self, domain_handle):
		status = NTStatus.MORE_ENTRIES
		enumerationContext = 0
		while status == NTStatus.MORE_ENTRIES:
			try:
				#userAccountControl=USER_NORMAL_ACCOUNT,
				resp = await samr.hSamrEnumerateUsersInDomain(self.dce, domain_handle,  enumerationContext=enumerationContext)
			except DCERPCException as e:
				print(str(e))
				if str(e).find('STATUS_MORE_ENTRIES') < 0:
					raise
				resp = e.get_packet()
			
			for user in resp['Buffer']['Buffer']:
				user_sid = '%s-%s' % (self.domain_handles[domain_handle], user['RelativeId'])
				yield user['Name'], user_sid
			enumerationContext = resp['EnumerationContext'] 
			status = NTStatus(resp['ErrorCode'])

	async def open_user(self, domain_handle, user_id, access_level = samr.MAXIMUM_ALLOWED):
		try:
			resp = await samr.hSamrOpenUser(self.dce, domain_handle, userId=user_id, desiredAccess = access_level)
			self.user_handles[resp['UserHandle']] = self.domain_handles[domain_handle]
			return resp['UserHandle']
		except Exception as e:
			print(e)
			raise
		except DCERPCException as e:
			print(str(e))
			if str(e).find('STATUS_MORE_ENTRIES') < 0:
				raise
			resp = e.get_packet()
			
	async def get_user_info(self, user_handle, userInformationClass = samr.USER_INFORMATION_CLASS.UserGeneralInformation):
		resp = await samr.hSamrQueryInformationUser(self.dce, user_handle, userInformationClass = userInformationClass)
		return resp
			
	async def get_user_group_memberships(self, user_handle):
		#strange: the underlying function is not iterable
		try:
			resp = await samr.hSamrGetGroupsForUser(self.dce, user_handle)
		except Exception as e:
			print(str(e))
			if str(e).find('STATUS_MORE_ENTRIES') < 0:
				raise
			resp = e.get_packet()
		
		for group in resp['Groups']['Groups']:
			yield '%s-%s' % (self.user_handles[user_handle], group['RelativeId'])

	async def list_aliases(self, domain_handle):
		status = NTStatus.MORE_ENTRIES
		enumerationContext = 0
		while status == NTStatus.MORE_ENTRIES:
			try:
				resp = await samr.hSamrEnumerateAliasesInDomain(self.dce, domain_handle, enumerationContext=enumerationContext)
			except DCERPCException as e:
				print(str(e))
				if str(e).find('STATUS_MORE_ENTRIES') < 0:
					raise
				resp = e.get_packet()
		
			for alias in resp['Buffer']['Buffer']:
				yield (alias['Name'] , alias['RelativeId'])
			
			enumerationContext = resp['EnumerationContext'] 
			status = NTStatus(resp['ErrorCode'])
			print(status)

	async def open_alias(self, domain_handle, alias_id):
		try:
			resp = await samr.hSamrOpenAlias(self.dce, domain_handle, aliasId=alias_id)
			self.alias_handles[resp['AliasHandle']] = self.domain_handles[domain_handle]
			return resp['AliasHandle']
		except DCERPCException as e:
			print(str(e))
			if str(e).find('STATUS_MORE_ENTRIES') < 0:
				raise
			resp = e.get_packet()
	
	
	async def list_alias_members(self, alias_handle):
		#no iterators here...
		try:
			resp = await samr.hSamrGetMembersInAlias(self.dce, alias_handle)
			
			for sidr in resp['Members']['Sids']:
				yield sidr['SidPointer'].formatCanonical()
				
		except DCERPCException as e:
			print(str(e))
			if str(e).find('STATUS_MORE_ENTRIES') < 0:
				raise
			resp = e.get_packet()
			
			
	async def get_security_info(self, handle, securityInformation = DACL_SECURITY_INFORMATION):
		try:
			resp = await samr.hSamrQuerySecurityObject(self.dce, handle, securityInformation)
			return resp
				
		except DCERPCException as e:
			print(str(e))
			if str(e).find('STATUS_MORE_ENTRIES') < 0:
				raise
			resp = e.get_packet()