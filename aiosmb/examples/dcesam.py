
import asyncio
import traceback
import logging
import os

from aiosmb import logger
from aiosmb._version import __banner__
from aiosmb.commons.connection.factory import SMBConnectionFactory
from aiosmb.dcerpc.v5.interfaces.icprmgr import ICPRRPC
from aiosmb.dcerpc.v5.connection import DCERPC5Connection
from aiosmb.dcerpc.v5.common.connection.authentication import DCERPCAuth
from aiosmb.dcerpc.v5.interfaces.endpointmgr import EPM
from aiosmb.dcerpc.v5.interfaces.samrmgr import SAMRRPC


async def amain(url):
	try:
		print('[+] Parsing connection parameters...')
		su = SMBConnectionFactory.from_url(url)
		ip = su.get_target().get_hostname_or_ip()
		
		print('[+] Connecting to EPM...')
		target, err = await EPM.create_target(ip, SAMRRPC().service_uuid, dc_ip = su.get_target().dc_ip, domain = su.get_target().domain)
		if err is not None:
			raise err
		
		print('[+] Connecting to WKST service...')
		auth = DCERPCAuth.from_smb_gssapi(su.get_credential())
		connection = DCERPC5Connection(auth, target)
		rpc, err = await SAMRRPC.from_rpcconnection(connection, perform_dummy=True)
		if err is not None:
			raise err
		logger.debug('Service DCE Connected!')

		# now you can use service manager via DCE here


		async for domain, err in rpc.list_domains():
			if domain != 'TEST':
				continue

			dsid, err = await rpc.get_domain_sid(domain)
			if err is not None:
				raise err
			print(dsid)

			hdomain, err = await rpc.open_domain(dsid)
			if err is not None:
				raise err
			
			userinfo, err = await rpc.get_user_by_name(hdomain, 'Administrator')
			if err is not None:
				raise err
			
			print(userinfo.dump())


		#return


		async for domain, err in rpc.list_domains():
			if err is not None:
				raise err
			print(domain)

			dsid, err = await rpc.get_domain_sid(domain)
			if err is not None:
				raise err
			print(dsid)

			hdomain, err = await rpc.open_domain(dsid)
			if err is not None:
				raise err
			
			dinfo, err = await rpc.get_info(hdomain)
			if err is not None:
				raise err
			
			print(dinfo.dump())
			
			

			#async for user, usid, err in rpc.list_domain_users(hdomain):
			#	if err is not None:
			#		raise err
			#	print(user)

			async for gname, gsid, err in rpc.list_aliases(hdomain):
				if err is not None:
					raise err
				print(gname)

				halias, err = await rpc.open_alias(hdomain, gsid)
				if err is not None:
					raise err
				
				async for msid, err in rpc.list_alias_members(halias):
					if err is not None:
						raise err
					print(msid)
				
					usid = msid.split('-')[-1]
					print('User RID: %s' % usid)
					huser, err = await rpc.open_user(hdomain, int(usid))
					if err is not None:
						continue
						raise err
					
					print('OK!')
					uinfo, err = await rpc.get_user_info(huser)
					if err is not None:
						raise err
					print(uinfo.dump())
		
		print('[+] Finished!')
		return True, None
	except Exception as e:
		traceback.print_exc()
		return False, e


def main():
	import argparse

	parser = argparse.ArgumentParser(description='Remore Registry Service client via DCE/RPC')
	parser.add_argument('-v', '--verbose', action='count', default=0)
	parser.add_argument('smb_url', help = 'Connection string that describes the authentication and target. Example: smb+ntlm-password://TEST\\Administrator:password@10.10.10.2')
	
	args = parser.parse_args()
	print(__banner__)

	if args.verbose >=1:
		logger.setLevel(logging.DEBUG)

	asyncio.run(
		amain(
			args.smb_url,
		)
	)

if __name__ == '__main__':
	main()