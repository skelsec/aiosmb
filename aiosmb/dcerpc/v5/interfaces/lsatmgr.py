from aiosmb.dcerpc.v5.common.connection.smbdcefactory import SMBDCEFactory
from aiosmb.dcerpc.v5 import lsad
from aiosmb.dcerpc.v5 import lsat
from aiosmb.dcerpc.v5.interfaces.endpointmgr import EPM
from aiosmb.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
from aiosmb.wintypes.ntstatus import NTStatus
from aiosmb import logger
from aiosmb.dcerpc.v5.dtypes import NULL
from aiosmb.dcerpc.v5.interfaces.endpointmgr import EPM
from aiosmb.connection import SMBConnection
from aiosmb.dcerpc.v5.connection import DCERPC5Connection
from aiosmb.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_NONE,\
	RPC_C_AUTHN_LEVEL_CONNECT,\
	RPC_C_AUTHN_LEVEL_CALL,\
	RPC_C_AUTHN_LEVEL_PKT,\
	RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,\
	RPC_C_AUTHN_LEVEL_PKT_PRIVACY,\
	DCERPCException, RPC_C_AUTHN_GSS_NEGOTIATE

		
class LSADRPC:
	def __init__(self):
		self.service_pipename = r'\lsarpc'
		self.service_uuid = lsat.MSRPC_UUID_LSAT
		self.dce = None
		self.handle = None
		
		self.policy_handles = {} #handle to sid
		self.ph_ctr = 0
		
	async def __aenter__(self):
		return self
	
	async def __aexit__(self, exc_type, exc, traceback):
		await self.close()
		return True, None
	
	async def close(self):		
		try:
			if self.dce:
				for hid in self.policy_handles:
					try:
						await lsad.hLsarClose(self.dce, self.policy_handles[hid])
					except:
						logger.exception()
						pass

				try:
					await self.dce.disconnect()
				except:
					pass
				return True, None
		except Exception as e:
			return None, e
	
	@staticmethod
	async def from_rpcconnection(connection:DCERPC5Connection, auth_level = None, open:bool = True, perform_dummy:bool = False):
		try:
			service = LSADRPC()
			service.dce = connection
			
			service.dce.set_auth_level(auth_level)
			if auth_level is None:
				service.dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY) #secure default :P
			
			_, err = await service.dce.connect()
			if err is not None:
				raise err
			
			_, err = await service.dce.bind(LSADRPC().service_uuid)
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
			rpctransport = SMBDCEFactory(connection, filename=LSADRPC().service_pipename)		
			service, err = await LSADRPC.from_rpcconnection(rpctransport.get_dce_rpc(), auth_level=auth_level, open=open, perform_dummy = perform_dummy)	
			if err is not None:
				raise err

			return service, None
		except Exception as e:
			return None, e
	
	async def open_policy2(self, permissions = MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES):
		try:
			resp, err = await lsad.hLsarOpenPolicy2(self.dce, permissions)
			if err is not None:
				raise err
			ph = resp['PolicyHandle']
			self.policy_handles[self.ph_ctr] = ph
			t = self.ph_ctr
			self.ph_ctr += 1
			return t, None
		except Exception as e:
			return None, e

	async def get_domain_sid(self, policy_handle):
		try:
			resp, err = await lsad.hLsarQueryInformationPolicy2(self.dce, self.policy_handles[policy_handle], lsad.POLICY_INFORMATION_CLASS.PolicyPrimaryDomainInformation)
			if err is not None:
				raise err
			domain_sid = resp['PolicyInformation']['PolicyPrimaryDomainInfo']['Sid'].formatCanonical()
			return domain_sid, None
		except Exception as e:
			return None, e

	async def get_host_sid(self, policy_handle):
		try:
			resp, err = await lsad.hLsarQueryInformationPolicy2(self.dce, self.policy_handles[policy_handle], lsad.POLICY_INFORMATION_CLASS.PolicyAccountDomainInformation)
			if err is not None:
				raise err
			host_sid = resp['PolicyInformation']['PolicyAccountDomainInfo']['DomainSid'].formatCanonical()
			return host_sid, None
		except Exception as e:
			return None, e

	async def lookup_sids(self, policy_handle, sids, lookup_level = lsat.LSAP_LOOKUP_LEVEL.enumItems.LsapLookupWksta):
		"""
		sids: list of string sid
		"""
		try:
			resp, err = await lsat.hLsarLookupSids(self.dce, self.policy_handles[policy_handle], sids, lookup_level)
			if err is not None:
				raise err
			if lookup_level == lsat.LSAP_LOOKUP_LEVEL.enumItems.LsapLookupWksta:
				domains = []
				for entry in resp['ReferencedDomains']['Domains']:
					domains.append(entry['Name'])

				for entry in resp['TranslatedNames']['Names']:
					domain = domains[entry['DomainIndex']]
					yield domain, entry['Name'], None
			else:
				yield resp, None
		except Exception as e:
			yield None, e
			return
		
	async def retrieve_private_data(self, policy_handle, key_name):
		try:
			resp, err = await lsad.hLsarRetrievePrivateData(self.dce, self.policy_handles[policy_handle], key_name)
			if err is not None:
				return None, err
			return resp, None
		except Exception as e:
			return None, e
			


async def amain(url):
	import traceback
	import hashlib
	from aiosmb.commons.connection.url import SMBConnectionURL
	from aiosmb.commons.interfaces.machine import SMBMachine
	from aiosmb.wintypes.dtyp.constrcuted_security.guid import GUID

	url = SMBConnectionURL(url)
	connection = url.get_connection()
	_, err = await connection.login()
	if err is not None:
		print(err)
		raise err
	
	async with LSADRPC(connection) as b:
		_, err = await b.connect()
		if err is not None:
			print(err)
			print(traceback.format_tb(err.__traceback__))
			return
		ph, err = await b.open_policy2()
		if err is not None:
			print(err)
			print(traceback.format_tb(err.__traceback__))
			return
		print(ph)

		data, err = await b.retrieve_private_data(ph, 'G$BCKUPKEY_PREFERRED')
		if err is not None:
			print(err)
			print(traceback.format_tb(err.__traceback__))
			return
		print(data)

		guid = GUID.from_bytes(data)
		g = 'G$BCKUPKEY_%s' % str(guid)
		print(g)

		data, err = await b.retrieve_private_data(ph, g)
		if err is not None:
			print(err)
			print(traceback.format_tb(err.__traceback__))
			return
		print(data)


if __name__ == '__main__':
	import asyncio
	url = 'smb2+ntlm-password://TEST\\Administrator:QLFbT8zkiFGlJuf0B3Qq@10.10.10.2'
	asyncio.run(amain(url))
