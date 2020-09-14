
import asyncio

from aiosmb import logger
from aiosmb.commons.connection.params import SMBConnectionParams
from aiosmb.commons.connection.url import SMBConnectionURL
from aiosmb.commons.interfaces.machine import SMBMachine
from aiosmb.dcerpc.v5.common.service import SMBServiceStatus
from aiosmb.external.aiocmd.aiocmd import aiocmd
import enum

class SMBREG_COMMAND(enum.Enum):
	READ = 'R'
	ENUMVALUE = 'EV'
	ENUMKEY = 'EK'


async def amain():
	import argparse
	import sys
	import logging
	

	parser = argparse.ArgumentParser(description='Registry manipulation via SMB')
	SMBConnectionParams.extend_parser(parser)
	parser.add_argument('-v', '--verbose', action='count', default=0)
	parser.add_argument('url', help='Connection URL base, target can be set to anything. Owerrides all parameter based connection settings! Example: "smb2+ntlm-password://TEST\\victim@test"')
	parser.add_argument('commands', nargs='*', help = 'Commands in the following format: "r:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest:Negotiate"')

	args = parser.parse_args()

	if args.verbose >=1:
		logger.setLevel(logging.DEBUG)

	if args.verbose > 2:
		print('setting deepdebug')
		logger.setLevel(1) #enabling deep debug
		asyncio.get_event_loop().set_debug(True)
		logging.basicConfig(level=logging.DEBUG)
	
	commands = []
	smb_url = None
	if args.url is not None:
		smb_url = args.url
	else:
		try:
			smb_url = SMBConnectionParams.parse_args(args)
		except Exception as e:
			print('Either URL or all connection parameters must be set! Error: %s' % str(e))
			sys.exit(1)
	
	#pre-parsing commands
	for cmd in args.commands:
		c, path = cmd.split(':', 1)
		c = SMBREG_COMMAND(c.upper())
		commands.append((c, path))

	connection = SMBConnectionURL(smb_url).get_connection()
	_, err = await connection.login()
	if err is not None:
		print('Login failed! Reason: %s' % str(err))
		return
	machine = SMBMachine(connection)
	#async for srv, err in machine.list_services():
	#	if err is not None:
	#		print(err)
	#		return
	#	print(srv)
	registry_srv_status, err = await machine.check_service_status("RemoteRegistry")
	if err is not None:
		print('Check service status error! %s' % err)
		return

	if registry_srv_status != SMBServiceStatus.RUNNING:
		logger.info('RemoteRegistry is not running! Starting it now..')
		res, err = await machine.enable_service("RemoteRegistry")
		if err is not None:
			print(err)
			return
		await asyncio.sleep(5) #waiting for service to start up
	
	reg_api, err = await machine.get_regapi()
	if err is not None:
		print(err)
		return
	
	## do stuff
	for cmd, target in commands:
		if cmd == SMBREG_COMMAND.READ:
			regpath, name = target.split(':',1)
			hkey, err = await reg_api.OpenRegPath(regpath)
			if err is not None:
				print(err)
				continue
			
			val_type, value, err = await reg_api.QueryValue(hkey, name)
			if err is not None:
				print(err)
				continue
			print(value)
		
		elif cmd == SMBREG_COMMAND.ENUMVALUE:
			hkey, err = await reg_api.OpenRegPath(target)
			if err is not None:
				print(err)
				continue
			
			i=0
			while True:
				value_name, value_type, value_data, err = await reg_api.EnumValue(hkey, i)
				i+=1
				if err is not None:
					print(err)
					break
				print(value_name)
				print(value_type)
				print(value_data)
		
		elif cmd == SMBREG_COMMAND.ENUMKEY:
			hkey, err = await reg_api.OpenRegPath(target)
			if err is not None:
				print(err)
				continue
			i = 0
			while True:
				res, err = await reg_api.EnumKey(hkey, i)
				i+= 1
				if err is not None:
					print(err)
					break

				print(res)


def main():
	asyncio.run(amain())

if __name__ == '__main__':
	main()