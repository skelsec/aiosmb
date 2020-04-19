from aiosmb.dcerpc.v5.common.connection.smbdcefactory import SMBDCEFactory
from aiosmb.dcerpc.v5 import samr
from aiosmb.dcerpc.v5.dtypes import RPC_SID, DACL_SECURITY_INFORMATION
from aiosmb.wintypes.ntstatus import NTStatus
from aiosmb.dcerpc.v5.rpcrt import DCERPCException
from aiosmb import logger
import traceback
from aiosmb.commons.utils.extb import pprint_exc
from aiosmb.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, DCERPCException, RPC_C_AUTHN_GSS_NEGOTIATE
from aiosmb.commons.utils.decorators import red_gen, red, rr

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
		return True,None
	
	@red
	async def connect(self, open = True):
		rpctransport = SMBDCEFactory(self.connection, filename=r'\samr')
		self.dce = rpctransport.get_dce_rpc()
		await rr(self.dce.connect())
		await rr(self.dce.bind(samr.MSRPC_UUID_SAMR))
		
		if open == True:
			await rr(self.open())

		return True,None	
	
	@red
	async def open(self):
		if not self.dce:
			await rr(self.connect())
		
		ans, _= await rr(samr.hSamrConnect(self.dce))
		self.handle = ans['ServerHandle']

		return True,None
	
	@red
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
		
		return True,None
		
	@red
	async def close_handle(self, handle):
		resp, _ = await rr(samr.hSamrCloseHandle(self.dce, handle))
		return resp, None
	
	@red
	async def get_info(self, domain_handle, domainInformationClass = samr.DOMAIN_INFORMATION_CLASS.DomainGeneralInformation2):
		resp, _ = await rr(samr.hSamrQueryInformationDomain(self.dce, domain_handle, domainInformationClass = domainInformationClass))
		return resp, None
	
	@red_gen
	async def list_domains(self):
		status = NTStatus.MORE_ENTRIES
		enumerationContext = 0
		while status == NTStatus.MORE_ENTRIES:
			resp, err = await samr.hSamrEnumerateDomainsInSamServer(self.dce, self.handle, enumerationContext = enumerationContext)
			if err is not None:
				if err.error_code != NTStatus.MORE_ENTRIES.value:
					raise err
				resp = err.get_packet()
			
			for domain in resp['Buffer']['Buffer']:
				yield domain['Name'], None
			
			enumerationContext = resp['EnumerationContext']
			status = NTStatus(resp['ErrorCode'])
	
	@red
	async def get_domain_sid(self, domain_name):
		resp, _ = await rr(samr.hSamrLookupDomainInSamServer(self.dce, self.handle, domain_name))

		self.domain_ids[resp['DomainId'].formatCanonical()] = resp['DomainId']
		return resp['DomainId'].formatCanonical(), None
	
	@red
	async def open_domain(self, domain_sid, access_level = samr.MAXIMUM_ALLOWED):
		resp, _ = await rr(samr.hSamrOpenDomain(self.dce, self.handle, domainId = self.domain_ids[domain_sid], desiredAccess = access_level))
		self.domain_handles[resp['DomainHandle']] = domain_sid
		return resp['DomainHandle'], None
	
	@red_gen
	async def list_domain_users(self, domain_handle):
		user_type = samr.USER_NORMAL_ACCOUNT
		status = NTStatus.MORE_ENTRIES
		enumerationContext = 0
		while status == NTStatus.MORE_ENTRIES:
			resp, err = await samr.hSamrEnumerateUsersInDomain(self.dce, domain_handle, user_type, enumerationContext=enumerationContext)
			if err is not None:
				if err.error_code != NTStatus.MORE_ENTRIES.value:
					yield None, None, err
					return
				resp = err.get_packet()

			for user in resp['Buffer']['Buffer']:
				user_sid = '%s-%s' % (self.domain_handles[domain_handle], user['RelativeId'])
				yield user['Name'], user_sid, None

			enumerationContext = resp['EnumerationContext'] 
			status = NTStatus(resp['ErrorCode'])

	@red_gen	
	async def list_domain_groups(self, domain_handle):
		status = NTStatus.MORE_ENTRIES
		enumerationContext = 0
		while status == NTStatus.MORE_ENTRIES:
			resp, err = await samr.hSamrEnumerateGroupsInDomain(self.dce, domain_handle, enumerationContext=enumerationContext)
			if err is not None:
				if err.error_code != NTStatus.MORE_ENTRIES.value:
					raise err
				resp = err.get_packet()

			for group in resp['Buffer']['Buffer']:
				group_sid = '%s-%s' % (self.domain_handles[domain_handle], group['RelativeId'])
				yield group['Name'], group_sid, None
			enumerationContext = resp['EnumerationContext'] 
			status = NTStatus(resp['ErrorCode'])
			
	@red_gen
	async def enumerate_users(self, domain_handle):
		status = NTStatus.MORE_ENTRIES
		enumerationContext = 0
		while status == NTStatus.MORE_ENTRIES:
			resp, err = await samr.hSamrEnumerateUsersInDomain(self.dce, domain_handle,  enumerationContext=enumerationContext)
			if err is not None:
				if err.error_code != NTStatus.MORE_ENTRIES.value:
					raise err
				resp = err.get_packet()

			for user in resp['Buffer']['Buffer']:
				user_sid = '%s-%s' % (self.domain_handles[domain_handle], user['RelativeId'])
				yield user['Name'], user_sid, None
			enumerationContext = resp['EnumerationContext'] 
			status = NTStatus(resp['ErrorCode'])

	@red
	async def open_user(self, domain_handle, user_id, access_level = samr.MAXIMUM_ALLOWED):
		resp, _ = await rr(samr.hSamrOpenUser(self.dce, domain_handle, userId=user_id, desiredAccess = access_level))
		self.user_handles[resp['UserHandle']] = self.domain_handles[domain_handle]
		return resp['UserHandle'], None
	
	@red
	async def get_user_info(self, user_handle, userInformationClass = samr.USER_INFORMATION_CLASS.UserGeneralInformation):
		resp, _ = await rr(samr.hSamrQueryInformationUser(self.dce, user_handle, userInformationClass = userInformationClass))
		return resp, None
	
	@red_gen
	async def get_user_group_memberships(self, user_handle):
		resp, _ = await rr(samr.hSamrGetGroupsForUser(self.dce, user_handle))
		
		for group in resp['Groups']['Groups']:
			yield '%s-%s' % (self.user_handles[user_handle], group['RelativeId']) , None

	@red_gen
	async def list_aliases(self, domain_handle):
		status = NTStatus.MORE_ENTRIES
		enumerationContext = 0
		while status == NTStatus.MORE_ENTRIES:
			resp, err = await samr.hSamrEnumerateAliasesInDomain(self.dce, domain_handle, enumerationContext=enumerationContext)
			if err is not None:
				if err.error_code != NTStatus.MORE_ENTRIES.value:
					raise err
				resp = err.get_packet()

			for alias in resp['Buffer']['Buffer']:
				yield alias['Name'] , alias['RelativeId'], None
			
			enumerationContext = resp['EnumerationContext'] 
			status = NTStatus(resp['ErrorCode'])

	@red
	async def open_alias(self, domain_handle, alias_id):
		resp, _ = await rr(samr.hSamrOpenAlias(self.dce, domain_handle, aliasId=alias_id))
		self.alias_handles[resp['AliasHandle']] = self.domain_handles[domain_handle]
		return resp['AliasHandle'], None
	
	@red_gen
	async def list_alias_members(self, alias_handle):
		resp, _ = await rr(samr.hSamrGetMembersInAlias(self.dce, alias_handle))
			
		for sidr in resp['Members']['Sids']:
			yield sidr['SidPointer'].formatCanonical(), None
	
	@red
	async def get_security_info(self, handle, securityInformation = DACL_SECURITY_INFORMATION):
		resp, _ = await rr(samr.hSamrQuerySecurityObject(self.dce, handle, securityInformation))
		return resp, None