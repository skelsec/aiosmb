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
from aiosmb.dcerpc.v5.uuid import bin_to_string
from aiosmb.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_NONE,\
	RPC_C_AUTHN_LEVEL_CONNECT,\
	RPC_C_AUTHN_LEVEL_CALL,\
	RPC_C_AUTHN_LEVEL_PKT,\
	RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,\
	RPC_C_AUTHN_LEVEL_PKT_PRIVACY,\
	DCERPCException, RPC_C_AUTHN_GSS_NEGOTIATE
from unicrypto.symmetric import cipherMODE, DES, expand_DES_key
from winacl.dtyp.wcee.backupkey import PREFERRED_BACKUP_KEY
from winacl.dtyp.wcee.pvkfile import PVKFile
from contextlib import asynccontextmanager

@asynccontextmanager
async def lsadrpc_from_smb(connection, auth_level=None, open=True, perform_dummy=False):
    instance, err = await LSADRPC.from_smbconnection(connection, auth_level=auth_level, open=open, perform_dummy=perform_dummy)
    if err:
        # Handle or raise the error as appropriate
        raise err
    try:
        yield instance
    finally:
        await instance.close()

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
				#service.dce.set_auth_level(RPC_C_AUTHN_LEVEL_NONE) #secure default :P

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
			if auth_level is None:
				auth_level = RPC_C_AUTHN_LEVEL_NONE
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
			secret = self.decrypt_secret(resp)
			return secret, None
		except Exception as e:
			return None, e
	
	async def open_secret(self, policy_handle, secret_name):
		resp, err = await lsad.hLsarOpenSecret(self.dce, self.policy_handles[policy_handle], secret_name)
		if err is not None:
			return None, err
		return resp['SecretHandle'], err

	async def query_secret(self, secret_handle):
		resp, err = await lsad.hLsarQuerySecret(self.dce, secret_handle)
		if err is not None:
			return None, err
		enc_secret = b''.join(resp['EncryptedCurrentValue']['Buffer'])
		secret = self.decrypt_secret(enc_secret)
		return secret, err

	async def get_backupkeys(self):
		try:
			ph, err = await self.open_policy2(lsad.POLICY_GET_PRIVATE_INFORMATION)
			if err is not None:
				raise err
			
			results = {}
			for keyname in ['G$BCKUPKEY_PREFERRED', 'G$BCKUPKEY_P']:
				res = {}
				guid_bytes, err = await self.retrieve_private_data(ph, keyname)
				if err is not None:
					raise err
				
				guid = 'G$BCKUPKEY_%s' % bin_to_string(guid_bytes)
				keystruct, err = await self.retrieve_private_data(ph, guid)
				if err is not None:
					raise err

				keyversion = int.from_bytes(keystruct[:4], byteorder='little', signed = False)
				if keyversion == 1:
					keydata = keystruct[4:]
					res['legacykey'] = keydata
				elif keyversion == 2:
					pbk = PREFERRED_BACKUP_KEY.from_bytes(keystruct)
					pvk = PVKFile.construct_unencrypted('RSA2', pbk.keydata)
					certificate = pbk.certdata
					res['pvk'] = pvk
					res['certificate'] = certificate

				results[guid] = res
			
			return results, None
			
		except Exception as e:
			return None, e

	def decrypt_secret(self, encdata):
		# [MS-LSAD] Section 5.1.2
		# taken from impacket
		key = self.dce.get_session_key()
		decdata = b''
		key0 = key
		for _ in range(0, len(encdata), 8):
			chunk = encdata[:8]
			tkey = expand_DES_key(key0[:7]) #transformkey
			ctx = DES(tkey, cipherMODE.ECB)
			decdata += ctx.decrypt(chunk)
			key0 = key0[7:]
			encdata = encdata[8:]
			if len(key0) < 7:
				key0 = key[len(key0):]
		secret = lsad.LSA_SECRET_XP(decdata)
		return secret['Secret']

	async def get_username(self):
		"""Returns the username of the current user"""
		try:
			ans, err = await lsat.hLsarGetUserName(self.dce)
			if err is not None:
				raise err
			return ans['UserName'], None
		except Exception as e:
			return None, e
		
	async def get_sid_for_user(self, policy_handle, username:str):
		"""Returns the SID of the user specified by username"""
		try:
			ans, err = await lsat.hLsarLookupNames(self.dce, self.policy_handles[policy_handle], [username])
			if err is not None:
				raise err
			domain_name = ans['ReferencedDomains']['Domains'][0]['Name']
			domain_sid = ans['ReferencedDomains']['Domains'][0]['Sid'].formatCanonical()
			user_rid = ans['TranslatedSids']['Sids'][0]['RelativeId']
			usersid = '%s-%s' % (domain_sid, user_rid)
			return usersid, domain_name, user_rid, None
		except Exception as e:
			print(err)
			return None, e


async def amain(url):
	enc_des = """
	e80089d6f0b1f19e
	c669ca27496f2fc1
	77304427d10d993c
	"""
	dec_des = """
	1000000001000000 
	0503fa2ece589243
	a8117ee5881c8c25
	"""

	import traceback
	import hashlib
	from aiosmb.commons.connection.factory import SMBConnectionFactory
	from aiosmb.commons.interfaces.machine import SMBMachine
	from aiosmb.wintypes.dtyp.constrcuted_security.guid import GUID

	url = SMBConnectionFactory.from_url(url)
	connection = url.get_connection()
	_, err = await connection.login()
	if err is not None:
		print(err)
		raise err
	
	print('SMB Connected!')
	
	b = None
	try:
		b, err = await LSADRPC.from_smbconnection(connection)
		if err is not None:
			print(err)
			print(traceback.format_tb(err.__traceback__))
			return
		
		keys, err = await b.get_backupkeys()
		if err is not None:
			raise err
		
		print(keys)

	except:
		traceback.print_exc()
		if b is not None:
			await b.close()



if __name__ == '__main__':
	import asyncio
	#url = 'smb3+kerberos-password://TEST\\Administrator:Passw0rd!1@win2019ad.test.corp/?dc=10.10.10.2'
	url = 'smb2+ntlm-password://TEST\\dadmin:Passw0rd!1alma@win2019ad.test.corp/?dc=10.10.10.2'
	#url = 'smb2+ntlm-password://TEST\\victim:Passw0rd!1@10.10.10.2'
	asyncio.run(amain(url))
