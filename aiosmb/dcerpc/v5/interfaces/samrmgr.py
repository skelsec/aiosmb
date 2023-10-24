from aiosmb.dcerpc.v5.common.connection.smbdcefactory import SMBDCEFactory
from aiosmb.connection import SMBConnection
from aiosmb.dcerpc.v5.connection import DCERPC5Connection
from aiosmb.dcerpc.v5 import samr
from aiosmb.dcerpc.v5.dtypes import RPC_SID, DACL_SECURITY_INFORMATION
from aiosmb.wintypes.ntstatus import NTStatus
from aiosmb.dcerpc.v5.rpcrt import DCERPCException
from aiosmb import logger
import traceback
from aiosmb.commons.utils.extb import pprint_exc
from aiosmb.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, DCERPCException, RPC_C_AUTHN_GSS_NEGOTIATE
from aiosmb.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_NONE,\
	RPC_C_AUTHN_LEVEL_CONNECT,\
	RPC_C_AUTHN_LEVEL_CALL,\
	RPC_C_AUTHN_LEVEL_PKT,\
	RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,\
	RPC_C_AUTHN_LEVEL_PKT_PRIVACY,\
	DCERPCException, RPC_C_AUTHN_GSS_NEGOTIATE

from contextlib import asynccontextmanager

@asynccontextmanager
async def samrrpc_from_smb(connection, auth_level=None, open=True, perform_dummy=False):
    instance, err = await SAMRRPC.from_smbconnection(connection, auth_level=auth_level, open=open, perform_dummy=perform_dummy)
    if err:
        # Handle or raise the error as appropriate
        raise err
    try:
        yield instance
    finally:
        await instance.close()

class SAMRRPC:
	def __init__(self):
		self.service_pipename = r'\samr'
		self.service_uuid = samr.MSRPC_UUID_SAMR
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
	
	@staticmethod
	async def from_rpcconnection(connection:DCERPC5Connection, auth_level = None, open:bool = True, perform_dummy:bool = False):
		try:
			service = SAMRRPC()
			service.dce = connection
			
			service.dce.set_auth_level(auth_level)
			if auth_level is None:
				service.dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY) #secure default :P 
			
			_, err = await service.dce.connect()
			if err is not None:
				raise err
			
			_, err = await service.dce.bind(service.service_uuid)
			if err is not None:
				raise err
			
			if open is True:
				_, err = await service.open()
				if err is not None:
					raise err
				
			return service, None
		except Exception as e:
			return False, e
	
	@staticmethod
	async def from_smbconnection(connection:SMBConnection, auth_level = None, open:bool = True, perform_dummy:bool = False):
		"""
		Creates the connection to the service using an established SMBConnection.
		This connection will use the given SMBConnection as transport layer.
		"""
		try:
			if auth_level is None:
				#for SMB connection no extra auth needed
				auth_level = RPC_C_AUTHN_LEVEL_NONE
			rpctransport = SMBDCEFactory(connection, filename=SAMRRPC().service_pipename)		
			service, err = await SAMRRPC.from_rpcconnection(rpctransport.get_dce_rpc(), auth_level=auth_level, open=open, perform_dummy = perform_dummy)	
			if err is not None:
				raise err

			return service, None
		except Exception as e:
			return None, e
	
	async def open(self):
		if not self.dce:
			_, err = await self.connect()
			if err is not None:
				raise err

		ans, err = await samr.hSamrConnect(self.dce)
		if err is not None:
			raise err

		self.handle = ans['ServerHandle']

		return True,None
	
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
		
	async def close_handle(self, handle):
		resp, err = await samr.hSamrCloseHandle(self.dce, handle)
		if err is not None:
			return None, err
		return resp, None
	
	async def get_info(self, domain_handle, domainInformationClass = samr.DOMAIN_INFORMATION_CLASS.DomainGeneralInformation2):
		resp, err = await samr.hSamrQueryInformationDomain(self.dce, domain_handle, domainInformationClass = domainInformationClass)
		if err is not None:
			return None, err
		return resp, None
	
	async def get_user_by_name(self, domain_handle, username):
		resp, err = await samr.hSamrLookupNamesInDomain(self.dce, domain_handle, [username])
		if err is not None:
			print(err)
			return None, err
		
		print(resp.dump())
		return resp, err
	
	async def list_domains(self):
		try:
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
		except Exception as e:
			yield None, e
	
	async def get_domain_sid(self, domain_name):
		try:
			resp, err = await samr.hSamrLookupDomainInSamServer(self.dce, self.handle, domain_name)
			if err is not None:
				raise err

			self.domain_ids[resp['DomainId'].formatCanonical()] = resp['DomainId']
			return resp['DomainId'].formatCanonical(), None
		except Exception as e:
			return None, e
	
	async def open_domain(self, domain_sid, access_level = samr.MAXIMUM_ALLOWED):
		try:
			resp, err = await samr.hSamrOpenDomain(self.dce, self.handle, domainId = self.domain_ids[domain_sid], desiredAccess = access_level)
			if err is not None:
				raise err
			self.domain_handles[resp['DomainHandle']] = domain_sid
			return resp['DomainHandle'], None
		except Exception as e:
			return None, e
	

	async def list_domain_users(self, domain_handle):
		try:
			user_type = samr.USER_NORMAL_ACCOUNT
			status = NTStatus.MORE_ENTRIES
			enumerationContext = 0
			while status == NTStatus.MORE_ENTRIES:
				resp, err = await samr.hSamrEnumerateUsersInDomain(self.dce, domain_handle, user_type, enumerationContext=enumerationContext)
				if err is not None:
					if err.error_code != NTStatus.MORE_ENTRIES.value:
						raise err
						return
					resp = err.get_packet()

				for user in resp['Buffer']['Buffer']:
					user_sid = '%s-%s' % (self.domain_handles[domain_handle], user['RelativeId'])
					yield user['Name'], user_sid, None

				enumerationContext = resp['EnumerationContext'] 
				status = NTStatus(resp['ErrorCode'])
		except Exception as e:
			yield None, None, e

	async def list_domain_groups(self, domain_handle):
		try:
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
		except Exception as e:
			yield None, None, e
	
	async def add_member_to_alias(self, alias_handle, sid):
		try:
			resp, err = await samr.hSamrAddMemberToAlias(self.dce, alias_handle, sid)
			if err is not None:
				if err.error_code != NTStatus.MORE_ENTRIES.value:
					raise err
				resp = err.get_packet()
			status = NTStatus(resp['ErrorCode'])
			result = status == NTStatus.SUCCESS
			return result, None
		except Exception as e:
			return None, e

	async def enumerate_users(self, domain_handle):
		try:
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
		except Exception as e:
			yield None, None, e

	async def open_user(self, domain_handle, user_id, access_level = samr.MAXIMUM_ALLOWED):
		try:
			resp, err = await samr.hSamrOpenUser(self.dce, domain_handle, userId=user_id, desiredAccess = access_level)
			if err is not None:
				raise err
			self.user_handles[resp['UserHandle']] = self.domain_handles[domain_handle]
			return resp['UserHandle'], None
		except Exception as e:
			return None, e
	
	async def get_user_info(self, user_handle, userInformationClass = samr.USER_INFORMATION_CLASS.UserGeneralInformation):
		try:
			resp, err = await samr.hSamrQueryInformationUser(self.dce, user_handle, userInformationClass = userInformationClass)
			return resp, None
		except Exception as e:
			return None, e

	
	async def get_user_group_memberships(self, user_handle):
		try:
			resp, err = await samr.hSamrGetGroupsForUser(self.dce, user_handle)
			if err is not None:
				raise err
			
			for group in resp['Groups']['Groups']:
				yield '%s-%s' % (self.user_handles[user_handle], group['RelativeId']) , None
		except Exception as e:
			yield None, e

	async def list_aliases(self, domain_handle):
		try:
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
		except Exception as e:
			yield None, None, e

	async def open_alias(self, domain_handle, alias_id):
		try:
			resp, err = await samr.hSamrOpenAlias(self.dce, domain_handle, aliasId=alias_id)
			if err is not None:
				raise err
			self.alias_handles[resp['AliasHandle']] = self.domain_handles[domain_handle]
			return resp['AliasHandle'], None
		except Exception as e:
			return None, e
	
	async def list_alias_members(self, alias_handle):
		try:
			resp, err = await samr.hSamrGetMembersInAlias(self.dce, alias_handle)
			if err is not None:
				raise err
			
			for sidr in resp['Members']['Sids']:
				yield sidr['SidPointer'].formatCanonical(), None
		except Exception as e:
			yield None, e
	
	async def get_security_info(self, handle, securityInformation = DACL_SECURITY_INFORMATION):
		try:
			resp, err = await samr.hSamrQuerySecurityObject(self.dce, handle, securityInformation)
			if err is not None:
				raise err
			return resp, None
		except Exception as e:
			return None, e