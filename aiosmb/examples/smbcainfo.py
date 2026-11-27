
import asyncio
import json
import logging
import traceback

from aiosmb import logger
from aiosmb._version import __banner__
from aiosmb.commons.connection.factory import SMBConnectionFactory
from aiosmb.commons.interfaces.machine import SMBMachine
from aiosmb.dcerpc.v5.dcom.certadmin import EditFlags, InterfaceFlags, CAAccessMask
from aiosmb.examples._cli import (
	CONNECTION_EPILOG,
	add_url_help,
	add_verbosity,
	make_parser,
)

from winacl.dtyp.ace import ACEType

# szOID_NTDS_CA_SECURITY_EXT, the extension carrying the SID of the requester
SID_SECURITY_EXTENSION = '1.3.6.1.4.1.311.25.2'

ACE_TYPE_NAMES = {
	ACEType.ACCESS_ALLOWED_ACE_TYPE: 'Allow',
	ACEType.ACCESS_DENIED_ACE_TYPE: 'Deny',
}


def flag_names(flags):
	return [flag.name for flag in type(flags) if flag in flags]


def find_issues(config):
	"""Checks the CA configuration for the misconfigurations readable from it."""
	issues = []
	if EditFlags.EDITF_ATTRIBUTESUBJECTALTNAME2 in config['edit_flags']:
		issues.append('ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 is set, requesters can specify the subject alternative name')
	if InterfaceFlags.IF_ENFORCEENCRYPTICERTREQUEST not in config['interface_flags']:
		issues.append('ESC11: IF_ENFORCEENCRYPTICERTREQUEST is not set, certificate requests over RPC can be relayed')
	if SID_SECURITY_EXTENSION in config['disable_extension_list']:
		issues.append('ESC16: the SID security extension (%s) is disabled' % SID_SECURITY_EXTENSION)
	return issues


def config_to_dict(config, sidnames = None):
	if sidnames is None:
		sidnames = {}
	sd = config['security_descriptor']
	aces = []
	if sd.Dacl is not None:
		for ace in sd.Dacl.aces:
			sid = str(ace.Sid)
			aces.append({
				'type': ACE_TYPE_NAMES.get(ace.AceType, ace.AceType.name),
				'sid': sid,
				'name': sidnames.get(sid),
				'mask': int(ace.Mask),
				'rights': flag_names(CAAccessMask(int(ace.Mask) & 0x30F)),
			})

	owner = str(sd.Owner) if sd.Owner is not None else None
	return {
		'ca_name': config['ca_name'],
		'edit_flags': int(config['edit_flags']),
		'edit_flag_names': flag_names(config['edit_flags']),
		'interface_flags': int(config['interface_flags']),
		'interface_flag_names': flag_names(config['interface_flags']),
		'disable_extension_list': config['disable_extension_list'],
		'owner': owner,
		'owner_name': sidnames.get(owner),
		'aces': aces,
		'sddl': sd.to_sddl(),
		'issues': find_issues(config),
	}


def print_config(res):
	print('[*] CA name: %s' % res['ca_name'])
	print('[*] EditFlags: 0x%08x' % res['edit_flags'])
	for name in res['edit_flag_names']:
		print('[*]   %s' % name)
	print('[*] InterfaceFlags: 0x%08x' % res['interface_flags'])
	for name in res['interface_flag_names']:
		print('[*]   %s' % name)
	print('[*] DisableExtensionList: %s' % (', '.join(res['disable_extension_list']) or '<empty>'))

	def principal(sid, name):
		return sid if name is None else '%s (%s)' % (name, sid)

	print('[*] Owner: %s' % principal(res['owner'], res['owner_name']))
	print('[*] Access rights:')
	for ace in res['aces']:
		rights = ', '.join(ace['rights']) or '0x%x' % ace['mask']
		print('[*]   %-5s %s: %s' % (ace['type'], principal(ace['sid'], ace['name']), rights))

	if len(res['issues']) == 0:
		print('[+] No misconfiguration found in the CA settings')
	for issue in res['issues']:
		print('[!] %s' % issue)


async def amain(url, ca_name = None, resolve = False, to_json = False):
	try:
		connection = SMBConnectionFactory.from_url(url).get_connection()
		_, err = await connection.login()
		if err is not None:
			raise err

		async with connection:
			machine = SMBMachine(connection)
			config, err = await machine.get_ca_config_dcom(ca_name)
			if err is not None:
				raise err

			sidnames = {}
			if resolve is True:
				sd = config['security_descriptor']
				sids = [str(ace.Sid) for ace in sd.Dacl.aces] if sd.Dacl is not None else []
				if sd.Owner is not None:
					sids.append(str(sd.Owner))
				for sid in set(sids):
					username, domain, err = await machine.resolve_sid_to_username(sid)
					if err is None:
						sidnames[sid] = '%s\\%s' % (domain, username)

		res = config_to_dict(config, sidnames)
		if to_json is True:
			print(json.dumps(res, indent = 4))
		else:
			print_config(res)
		return res, None
	except Exception as e:
		logger.debug(traceback.format_exc())
		print('[-] Failed to read the CA configuration! Reason: %s' % e)
		return None, e


def build_parser(prog=None):
	parser = make_parser(
		'Read the security configuration of an AD CS certificate authority',
		prog=prog,
		epilog=(
			'The configuration is read via the MS-CSRA (ICertAdminD2) DCOM interface,\n'
			'which needs TCP/135 plus a dynamic RPC port, and administrative rights\n'
			'on the CA. Nothing is modified on the server.\n\n'
			+ CONNECTION_EPILOG
		),
	)
	add_url_help(parser)

	parser.add_argument(
		'--ca',
		metavar='NAME',
		help='certificate authority name without the hostname; defaults to the CA active on the server',
	)

	output = parser.add_argument_group('output')
	output.add_argument(
		'--resolve',
		action='store_true',
		help='resolve the SIDs of the CA security descriptor to names via LSA',
	)
	output.add_argument(
		'--json',
		action='store_true',
		help='print the results in JSON format',
	)

	diagnostics = parser.add_argument_group('diagnostics')
	add_verbosity(diagnostics)

	parser.add_argument(
		'smb_url',
		metavar='URL',
		help='SMB connection URL for the certificate server; use --help-url',
	)
	return parser


def main(argv=None):
	parser = build_parser()

	args = parser.parse_args(argv)
	if args.json is False:
		print(__banner__)

	if args.verbose >=1:
		logger.setLevel(logging.DEBUG)

	_, err = asyncio.run(amain(args.smb_url, args.ca, args.resolve, args.json))
	if err is not None:
		raise SystemExit(1)

if __name__ == '__main__':
	main()
