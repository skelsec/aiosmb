
import asyncio
import os
import uuid
from cryptography.hazmat.primitives import hashes

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
from aiosmb.dcerpc.v5.common.dpapi_ng._crypto import DPAPINGBlob, decrypt_blob, GroupKeyEnvelope

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
		if isinstance(rootKey, uuid.UUID):
			rootKey = rootKey.bytes_le
		
		resp, err = await gkdi.hGetKey(self.dce, targetSD, rootKey, L0KeyID, L1KeyID, L2KeyID)
		if err is not None:
			return None, err
		gke_raw = b''.join(resp['ppbOut'])
		return GroupKeyEnvelope.unpack(gke_raw), None

	async def ncrypt_unprotect_secret(self, data):
		blob = DPAPINGBlob.unpack(data)
		target_sd = blob.protection_descriptor.get_target_sd()
		rk, err = await self.GetKey(
            target_sd,
            blob.key_identifier.root_key_identifier,
            blob.key_identifier.l0,
            blob.key_identifier.l1,
            blob.key_identifier.l2
        )
		if err is not None:
			return None, err
		
		return decrypt_blob(blob, rk), None



async def amain(url):
	import traceback
	from aiosmb.commons.connection.factory import SMBConnectionFactory

	data = bytes.fromhex('c571d901171889ade6040000000000003082045006092a864886f70d010703a08204413082043d02010231820409a2820405020104308203c704820370010000004b44534b03000000690100000f0000001e00000069d83cd1d10ebfac4620a164e805f56e080300001a0000001a000000444850420001000087a8e61db4b6663cffbbd19c651959998ceef608660dd0f25d2ceed4435e3b00e00df8f1d61957d4faf7df4561b2aa3016c3d91134096faa3bf4296d830e9a7c209e0c6497517abd5a8a9d306bcf67ed91f9e6725b4758c022e0b1ef4275bf7b6c5bfc11d45f9088b941f54eb1e59bb8bc39a0bf12307f5c4fdb70c581b23f76b63acae1caa6b7902d52526735488a0ef13c6d9a51bfa4ab3ad8347796524d8ef6a167b5a41825d967e144e5140564251ccacb83e6b486f6b3ca3f7971506026c0b857f689962856ded4010abd0be621c3a3960a54e710c375f26375d7014103a4b54330c198af126116d2276e11715f693877fad7ef09cadb094ae91e1a15973fb32c9b73134d0b2e77506660edbd484ca7b18f21ef205407f4793a1a0ba12510dbc15077be463fff4fed4aac0bb555be3a6c1b0c6b47b1bc3773bf7e8c6f62901228f8c28cbb18a55ae31341000a650196f931c77a57f2ddf463e5e9ec144b777de62aaab8a8628ac376d282d6ed3864e67982428ebc831d14348f6f2f9193b5045af2767164e1dfc967c1fb3f2e55a4bd1bffe83b9c80d052b985d182ea0adb2a3b7313d3fe14c8484b1e052588b9b7d2bbd2df016199ecd06e1557cd0915b3353bbb64e0ec377fd028370df92b52c7891428cdc67eb6184b523d1db246c32f63078490f00ef8d647d148d47954515e2327cfef98c582664b4c0f6cc4165911914ea310a2766c1ec2f5ba89d34002d975da503cc1809d05249fbad13f038a5a9fcb381601e04ec4b9b4f31f6ef25a3f56356d28590727df18f626a04caa3cd81ec602c22e0172a029256caf961a461e3ab61502ee6f27f1f134a88f37019534c7075cfe990ecfe535d1042ee1964af66a7e9e1167a0ffbd8359a6042a3117102240cf5cfd9c442259f0f3db45d1dd51a10e7f3e314250f2079b6122d84ebd9d405c83826d625c8a57dfe518389d645ee4daec02d48b7470e8419c84ed7bcabaf47ded6a1b1f132010d35004adf37fec61dfbc008fda690389ed945ea96bad5f3acffe0fe01f818cd10d01d58d012a37b98758928531d9bf5a614041f4cfbf4e00450057004c004100500053002e0043004f005200500000004e00450057004c004100500053002e0043004f00520050000000305106092b0601040182374a013044060a2b0601040182374a01013036303430320c035349440c2b532d312d352d32312d39323130343037302d313632323731323839342d333433363534373836332d353132300b060960864801650304012d04281a7b6922fc2450c81354ad9d3ce1020d24c327a071f57de6a74dddf3c0b4acb9cf3104efc06fb18d302b06092a864886f70d010701301e060960864801650304012e3011040c247911a21b5c7f4fd08359f9020110426af21e4b446113ce8c4ea45685ecf21d800047f61d5772452b3dab1efc093692f0e3fa3a16ad0fbdbe0df9e9953a934ff129848d34c1e1bc2f5eaefbe67eaa40f158759144b800325ac1307aafd02ce418badf3a9ed849d4053ffde7c2a3822d169377ebcce5c9a9a1a95261c02d49ba014edf882aa54141d0d9b5aa03155eef9f05a0233dbbd9c45f62f58f407cd25320')

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
	
	secret, err = await service.ncrypt_unprotect_secret(data)
	if err is not None:
		print('Failed to decrypt secret!')
		raise err
	print(secret)
	print(secret.decode('utf-16-le'))

if __name__ == '__main__':
	url = 'smb2+ntlm-password://NEWLAPS\\Administrator:Passw0rd!1@10.10.12.2'
	asyncio.run(amain(url))
	