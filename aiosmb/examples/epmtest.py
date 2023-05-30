import traceback
from asyauth.common.constants import asyauthSecret
from asyauth.common.credentials.spnego import SPNEGOCredential
from asyauth.common.credentials.ntlm import NTLMCredential
from aiosmb.dcerpc.v5.interfaces.endpointmgr import EPM
from aiosmb.dcerpc.v5.epm import KNOWN_UUIDS, KNOWN_PROTOCOLS
from aiosmb.dcerpc.v5.uuid import uuidtup_to_bin, generate, stringver_to_bin, bin_to_uuidtup, bin_to_string
from aiosmb.dcerpc.v5.common.connection.authentication import DCERPCAuth
from aiosmb.dcerpc.v5.connection import DCERPC5Connection
from aiosmb.dcerpc.v5.dtypes import NULL
from aiosmb.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_NONE,\
	RPC_C_AUTHN_LEVEL_CONNECT,\
	RPC_C_AUTHN_LEVEL_CALL,\
	RPC_C_AUTHN_LEVEL_PKT,\
	RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,\
	RPC_C_AUTHN_LEVEL_PKT_PRIVACY,\
	DCERPCException, RPC_C_AUTHN_GSS_NEGOTIATE
from aiosmb.dcerpc.v5.ndr import NDRCALL

class DummyOp(NDRCALL):
	opnum = 255
	structure = ()

async def amain():
	try:
		targets = []
		ip = '10.10.10.2'
		epm = EPM.from_address(ip)
		_, err = await epm.connect()
		if err is not None:
			raise err

		x, err = await epm.lookup()
		if err is not None:
			raise err
		
		await epm.disconnect()
		print(len(x))
		
		#print(x)
		for entry in x:
			version = '%s.%s' % (entry['tower']['Floors'][0]['MajorVersion'], entry['tower']['Floors'][0]['MinorVersion'])
			uuidstr = bin_to_string(entry['tower']['Floors'][0]['InterfaceUUID'])
			service_uuid = uuidtup_to_bin((uuidstr, version))
			#print(entry['tower']['Floors'][0]['InterfaceUUID'])
			#print(version)
			#print(service_uuid)
			

			target, err = await EPM.create_target(ip, service_uuid)
			print(err)
			
			if err is not None:
				if str(err).find('ept_s_not_registered') != -1:
					continue
				raise err
			
			targets.append((uuidstr, service_uuid, target))
		
		for uuidstr, service_uuid, target in targets:
			#print('UUID: %s' % uuidstr)
			#print('Target: %s' % target)
			cred = NTLMCredential(
				username = 'Administrator', 
				domain = 'TEST', 
				secret = 'Passw0rd!1', 
				stype = asyauthSecret.PASSWORD, 
			)

			gssapi = SPNEGOCredential([cred]).build_context()
			auth = DCERPCAuth.from_smb_gssapi(gssapi)
			connection = DCERPC5Connection(auth, target)
			connection.set_auth_level(RPC_C_AUTHN_LEVEL_CONNECT)
			try:
				_, err = await connection.connect()
				if err is not None:
					raise err

				_, err = await connection.bind(service_uuid)
				if err is not None:
					raise err
				
				req = DummyOp()
				_, err = await connection.request(req)
				if str(err).find('rpc_s_access_denied') == -1:
					proto = 'UNK'
					if uuidstr in KNOWN_PROTOCOLS:
						proto = KNOWN_PROTOCOLS[uuidstr]
					print('UUID : %s' % uuidstr)
					print('proto: %s' % proto)
					print('err  : %s' % err)
					print()
			except Exception as e:
				traceback.print_exc()
			finally:
				await connection.disconnect()


	except Exception as e:
		traceback.print_exc()

if __name__ == '__main__':
	import asyncio
	asyncio.run(amain())