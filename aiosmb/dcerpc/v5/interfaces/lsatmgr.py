from aiosmb.dcerpc.v5.common.connection.smbdcefactory import SMBDCEFactory
from aiosmb.dcerpc.v5 import lsad
from aiosmb.dcerpc.v5 import lsat
from aiosmb.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
from aiosmb.wintypes.ntstatus import NTStatus
from aiosmb import logger
from aiosmb.dcerpc.v5.dtypes import NULL
from aiosmb.commons.utils.decorators import red, rr, red_gen
		
class LSAD:
	def __init__(self, connection):
		self.connection = connection
		self.service_manager = None
		
		self.dce = None
		self.handle = None
		
		self.policy_handles = {} #handle to sid
		self.ph_ctr = 0
		
	async def __aenter__(self):
		return self
	
	async def __aexit__(self, exc_type, exc, traceback):
		await self.close()
		return True,None

	@red
	async def connect(self, open = True):
		rpctransport = SMBDCEFactory(self.connection, filename=r'\lsarpc')
		self.dce = rpctransport.get_dce_rpc()
		await rr(self.dce.connect())
		await rr(self.dce.bind(lsad.MSRPC_UUID_LSAD))
		return True,None
	
	@red
	async def close(self):		
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
			return
	
	@red
	async def open_policy2(self, permissions = MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES):
		resp, _ = await rr(lsad.hLsarOpenPolicy2(self.dce, permissions))
		ph = resp['PolicyHandle']
		self.policy_handles[self.ph_ctr] = ph
		t = self.ph_ctr
		self.ph_ctr += 1
		return t, None

	@red
	async def get_domain_sid(self, policy_handle):
		resp, _ = await rr(lsad.hLsarQueryInformationPolicy2(self.dce, self.policy_handles[policy_handle], lsad.POLICY_INFORMATION_CLASS.PolicyPrimaryDomainInformation))
		domain_sid = resp['PolicyInformation']['PolicyPrimaryDomainInfo']['Sid'].formatCanonical()
		return domain_sid, None

	@red
	async def get_host_sid(self, policy_handle):
		resp, _ = await rr(lsad.hLsarQueryInformationPolicy2(self.dce, self.policy_handles[policy_handle], lsad.POLICY_INFORMATION_CLASS.PolicyAccountDomainInformation))
		host_sid = resp['PolicyInformation']['PolicyAccountDomainInfo']['DomainSid'].formatCanonical()
		return host_sid, None

	@red_gen
	async def lookup_sids(self, policy_handle, sids, lookup_level = lsat.LSAP_LOOKUP_LEVEL.enumItems.LsapLookupWksta):
		"""
		sids: list of string sid
		"""
		resp, _ = await rr(lsat.hLsarLookupSids(self.dce, self.policy_handles[policy_handle], sids, lookup_level))
		if lookup_level == lsat.LSAP_LOOKUP_LEVEL.enumItems.LsapLookupWksta:
			domains = []
			for entry in resp['ReferencedDomains']['Domains']:
				domains.append(entry['Name'])

			for entry in resp['TranslatedNames']['Names']:
				domain = domains[entry['DomainIndex']]
				yield domain, entry['Name'], None
		else:
			yield resp, None
		
	@red
	async def retrieve_private_data(self, policy_handle, key_name):
		resp, err = await lsad.hLsarRetrievePrivateData(self.dce, self.policy_handles[policy_handle], key_name)
		if err is not None:
			return None, err
		return resp, None


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
	
	async with LSAD(connection) as b:
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
