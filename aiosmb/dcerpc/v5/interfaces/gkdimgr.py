
import asyncio
import os
from aiosmb.dcerpc.v5.common.connection.smbdcefactory import SMBDCEFactory
from aiosmb.dcerpc.v5.connection import DCERPC5Connection
from aiosmb.connection import SMBConnection
from aiosmb.dcerpc.v5 import gkdi
from aiosmb.dcerpc.v5.interfaces.endpointmgr import EPM
from aiosmb.dcerpc.v5.rpcrt import DCERPCException
from aiosmb import logger
from aiosmb.commons.utils.extb import pprint_exc
from aiosmb.dcerpc.v5.dtypes import NULL
from aiosmb.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_NONE, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, DCERPCException, RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_CONNECT
from aiosmb.dcerpc.v5.common.connection.authentication import DCERPCAuth
from aiosmb.dcerpc.v5.common.connection.target import DCERPCTarget

class GKDIMgr:
	def __init__(self):
		self.service_pipename = None
		self.service_uuid = gkdi.MSRPC_UUID_GKDI
		self.dce = None
		self.handle = None
	
	async def __aenter__(self):
		return self
	
	async def __aexit__(self, exc_type, exc, traceback):
		await self.close()
		return True, None
	
	async def close(self):		
		try:
			if self.dce:
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
			service = GKDIMgr()
			service.dce = connection
			
			#service.dce.set_auth_level(auth_level)
			# RPC_C_AUTHN_LEVEL_PKT_PRIVACY
			if auth_level is None:
				service.dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY) #secure default :P
			
			_, err = await service.dce.connect()
			if err is not None:
				raise err
			
			_, err = await service.dce.bind(GKDIMgr().service_uuid)
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
			rpctransport = SMBDCEFactory(connection)		
			service, err = await GKDIMgr.from_rpcconnection(rpctransport.get_dce_rpc(), auth_level=auth_level, open=open, perform_dummy = perform_dummy)	
			if err is not None:
				raise err

			return service, None
		except Exception as e:
			return None, e

	async def GetKey(self, targetSD, rootKey, L0KeyID, L1KeyID, L2KeyID):
		resp, err = await gkdi.hGetKey(self.dce, targetSD, rootKey, L0KeyID, L1KeyID, L2KeyID)
		if err is not None:
			return None, err
		print('RAW')
		print(b''.join(resp['ppbOut']).hex())
		print('------')
		return gkdi.GroupKeyEnvelope.from_bytes(b''.join(resp['ppbOut'])), None

	def calc_l2_key(self, target_l0idx, target_l1idx, taget_l2idx, response_l0idx, response_l1idx, response_l2idx, response_l1_key, response_l2_key, response_root_key_identifier, label = "KDS service\0".encode("utf-16-le")):
		l1 = response_l1idx
		l1_key = response_l1_key
		l2 = response_l2idx
		l2_key = response_l2_key

		if target_l1idx != l1:
			l1 -= 1

			while target_l1idx != l1:
				l1 -= 1
				l1_key = kdf(
					hash_algo,
					l1_key,
					label,
					compute_kdf_context(
						response_root_key_identifier,
						response_l0idx,
						l1,
						-1,
					),
					64,
				)

			l2 = 31
			l2_key = kdf(
				hash_algo,
				l1_key,
				label,
				compute_kdf_context(
					response_root_key_identifier,
					target_l0idx,
					l1,
					l2,
				),
				64,
			)

		while l2 != taget_l2idx:
			l2 -= 1

			# Key(SD, RK, L0, L1, n) = KDF(
			#   HashAlg,
			#   Key(SD, RK, L0, L1, n+1),
			#   "KDS service",
			#   RKID || L0 || L1 || n,
			#   512
			# )
			l2_key = kdf(
				hash_algo,
				l2_key,
				label,
				compute_kdf_context(
					response_root_key_identifier,
					response_l0idx,
					l1,
					l2,
				),
				64,
			)


async def amain(url):
	import traceback
	from aiosmb.commons.connection.factory import SMBConnectionFactory
	from aiosmb.commons.interfaces.machine import SMBMachine
	from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR, SE_SACL
	from winacl.dtyp.sid import SID
	from winacl.dtyp.ace import ACCESS_ALLOWED_ACE
	from winacl.dtyp.acl import ACL

	a1 = ACCESS_ALLOWED_ACE()
	a1.AceFlags = 0x00
	a1.Mask = 3
	a1.Sid = SID.from_string('S-1-5-21-92104070-1622712894-3436547863-512')

	a2 = ACCESS_ALLOWED_ACE()
	a2.AceFlags = 0x00
	a2.Mask = 2
	a2.Sid = SID.from_string('S-1-1-0')

	aces = [a1, a2]
	test = SECURITY_DESCRIPTOR()
	test.Owner = SID.from_string('S-1-5-18')
	test.Group = SID.from_string('S-1-5-18')
	test.Control = SE_SACL.SE_DACL_PRESENT | SE_SACL.SE_SELF_RELATIVE
	test.Dacl = ACL()
	test.Dacl.AclRevision = 0x02
	test.Dacl.aces = aces

	targetSD = test.to_bytes()
	print(SECURITY_DESCRIPTOR.from_bytes(targetSD))
	rootKey = bytes.fromhex('69d83cd1d10ebfac4620a164e805f56e')
	L0KeyID = 361
	L1KeyID = 15
	L2KeyID = 30


	url = SMBConnectionFactory.from_url(url)
	connection = url.get_connection()
	epm = EPM.from_smbconnection(connection)
	_, err = await epm.connect()
	if err is not None:
		raise err
	
	constring, err = await epm.map(GKDIMgr().service_uuid)
	if err is not None:
		raise err
	
	target = DCERPCTarget.from_connection_string(constring, smb_connection = connection)
	dcerpc_auth = DCERPCAuth.from_smb_gssapi(connection.gssapi)
	rpc_connection = DCERPC5Connection(dcerpc_auth, target)
	
	service, err = await GKDIMgr.from_rpcconnection(rpc_connection, open=open)
	if err is not None:
		print('Connection to service failed!')
		raise err
		
	res, err = await service.GetKey(targetSD, rootKey, L0KeyID, L1KeyID, L2KeyID)
	if err is not None:
		print('GetKey error!')
		print(err)
		print(traceback.format_tb(err.__traceback__))
		return
	print(res)
	print('!!!!!!!!!!!!!!!!!!!!!!!')

if __name__ == '__main__':
	url = 'smb2+ntlm-password://NEWLAPS\\Administrator:Passw0rd!1@10.10.12.2'
	asyncio.run(amain(url))
	