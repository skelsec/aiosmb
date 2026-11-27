
import asyncio
import logging

from aiosmb.commons.connection.target import SMBTarget
from aiosmb.commons.connection.factory import SMBConnectionFactory
from aiosmb.examples.scanners.smbfinger import SMBFingerScanner
from aiosmb.examples.scanners.smbiface import SMBInterfaceScanner
from aiosmb.examples.scanners.smbproto import SMBProtocolScanner
from aiosmb.examples.scanners.smbadmin import SMBAdminScanner
from aiosmb.examples.scanners.smbsession import SMBSessionScanner
from aiosmb.examples.scanners.smbprintnightmare import SMBPrintnightmareScanner
from aiosmb.examples.scanners.smbfile import SMBFileScanner
from aiosmb.examples.scanners.smbbrute import SMBBruteForceScanner
from aiosmb.examples.scanners.smbregsession import SMBRegSessionScanner
from aiosmb.examples.scanners.smbshare import SMBShareScanner
from aiosmb.examples.scanners.smbencryption import SMBEncryptionScanner
from aiosmb.examples._cli import (
	AIOSMBHelpFormatter,
	CONNECTION_EPILOG,
	add_url_help,
	make_parser,
)

smbscan_options = {
	'finger'    : (SMBFingerScanner, "SMB Finger grabs OS info. Only works with NTLM auth"),
	'interface' : (SMBInterfaceScanner, "Lists available interfaces on the remote hosts"),
	'proto'  : (SMBProtocolScanner, "SMB protocol version and NTLM signing checker"),
	'encryption': (SMBEncryptionScanner, "Checks whether SMB 3 encryption is enforced"),
	'admin'     : (SMBAdminScanner, "Checks if giver user is admin on the remote hosts"),
	'session'   : (SMBSessionScanner, "Lists SMB sessions"),
	'printnightmare': (SMBPrintnightmareScanner, "Checks hosts for printnightmare vulnerability"),
	'file' : (SMBFileScanner, 'Enumerates files and shares'),
	'brute'	 : (SMBBruteForceScanner, "Brute forces SMB logins"),
	'regsession': (SMBRegSessionScanner, "SMB Registry sessions"),
	'share' : (SMBShareScanner, "SMB Share scanner")
}

def build_parser(prog=None):
	global_help = (
		'Global options (place before TYPE):\n'
		'  -w/--worker-count N, -t/--timeout SECONDS, -d/--depth N,\n'
		'  --no-progress, -o/--out-file PATH, -e/--errors'
	)
	parser = make_parser(
		'Run SMB discovery, access, and security checks against many targets',
		prog=prog,
		epilog=(
			global_help + '\n\n' +
			CONNECTION_EPILOG
		),
	)
	add_url_help(parser)

	execution = parser.add_argument_group('execution')
	execution.add_argument(
		'-w',
		'--worker-count',
		type=int,
		default=100,
		metavar='N',
		help='maximum concurrent scanner workers',
	)
	execution.add_argument(
		'-t',
		'--timeout',
		type=int,
		default=10,
		metavar='SECONDS',
		help='timeout for each target',
	)
	execution.add_argument(
		'-d',
		'--depth',
		type=int,
		default=6,
		metavar='N',
		help='directory recursion depth used by the file scan',
	)

	output = parser.add_argument_group('output')
	output.add_argument(
		'--no-progress',
		action='store_true',
		help='disable the progress display',
	)
	output.add_argument(
		'-o',
		'--out-file',
		metavar='PATH',
		help='write scan results to this file',
	)
	output.add_argument(
		'-e',
		'--errors',
		action='store_true',
		help='include failed targets in output',
	)

	subparsers = parser.add_subparsers(
		title='scan types',
		dest='scantype',
		metavar='TYPE',
		required=True,
	)

	def add_scan(name, description, authenticated=False):
		subparser = subparsers.add_parser(
			name,
			help=description,
			description=description,
			formatter_class=AIOSMBHelpFormatter,
			epilog=(
				global_help + (
					'\n\n' + CONNECTION_EPILOG if authenticated else ''
				)
			),
		)
		if authenticated:
			add_url_help(subparser)
			subparser.add_argument(
				'url',
				metavar='URL',
				help='base SMB connection URL; use --help-url for the format',
			)
		return subparser

	def add_targets(subparser):
		subparser.add_argument(
			'targets',
			nargs='*',
			metavar='TARGET',
			help=(
				'hostname, IP address, CIDR range, or path to a file '
				'containing targets'
			),
		)

	fingerscan = add_scan(
		'finger',
		'Collect SMB and NTLM host information without authenticating',
	)
	add_targets(fingerscan)

	interfacescan = add_scan(
		'interface',
		'List server network interfaces using an authenticated session',
		authenticated=True,
	)
	add_targets(interfacescan)

	protoscan = add_scan(
		'proto',
		'Detect supported SMB dialects and signing requirements',
	)
	add_targets(protoscan)

	encryptionscan = add_scan(
		'encryption',
		'Check whether the server requires SMB 3 encryption',
		authenticated=True,
	)
	add_targets(encryptionscan)

	adminscan = add_scan(
		'admin',
		'Check whether the supplied account has administrative access',
		authenticated=True,
	)
	add_targets(adminscan)

	sessionscan = add_scan(
		'session',
		'List active SMB sessions',
		authenticated=True,
	)
	add_targets(sessionscan)

	printnightmarescan = add_scan(
		'printnightmare',
		'Check spooler RPC exposure associated with PrintNightmare',
		authenticated=True,
	)
	add_targets(printnightmarescan)

	filescan = add_scan(
		'file',
		'Enumerate shares, directories, and files',
		authenticated=True,
	)
	add_targets(filescan)

	brutescan = add_scan(
		'brute',
		'Test username/password candidates with per-user rate limiting',
	)
	brutescan.add_argument(
		'-d',
		'--domain',
		help='authentication domain for all username candidates',
	)
	brutescan.add_argument(
		'-u',
		'--usernames',
		required=True,
		metavar='USER_OR_FILE',
		help='one username or a file containing one username per line',
	)
	credentials = brutescan.add_mutually_exclusive_group(required=True)
	credentials.add_argument(
		'-p',
		'--passwords',
		metavar='FILE',
		help='file containing one password per line',
	)
	credentials.add_argument(
		'--up',
		action='store_true',
		help='test each username as its own password',
	)
	brutescan.add_argument(
		'-s',
		'--sleep-time',
		default=5,
		type=int,
		metavar='SECONDS',
		help='pause after max attempts for one user',
	)
	brutescan.add_argument(
		'-a',
		'--max-attempts',
		default=3,
		type=int,
		metavar='N',
		help='attempts per user before sleeping',
	)
	brutescan.add_argument(
		'target',
		metavar='TARGET',
		help='target hostname or IP address',
	)

	regsessionscan = add_scan(
		'regsession',
		'List logged-on users through the remote registry',
		authenticated=True,
	)
	add_targets(regsessionscan)

	sharescan = add_scan(
		'share',
		'Enumerate shares and optionally test write access',
		authenticated=True,
	)
	add_targets(sharescan)
	sharescan.add_argument(
		'-w',
		'--write-test',
		action='store_true',
		help='create and remove a temporary item to test share write access',
	)
	sharescan.add_argument(
		'-s',
		'--share-security',
		'--share-sd',
		dest='share_sd',
		action='store_true',
		help='fetch share security descriptors',
	)
	return parser


async def amain(argv=None):
	from asysocks.unicomm.common.scanner.targetgen import UniTargetGen, UniCredentialGen
	from asysocks.unicomm.common.scanner.scanner import UniScanner
	from aiosmb import logger

	parser = build_parser()
	args = parser.parse_args(argv)
	
	logger.setLevel(logging.CRITICAL)
	
	if args.scantype not in smbscan_options:
		print('Unknown scan type: "%s"' % args.scantype)
		return
	
	if args.scantype == 'finger':
		connectionfactory = SMBConnectionFactory.create_dummy()
		executor = smbscan_options[args.scantype][0](connectionfactory)
		tgen = UniTargetGen.from_list(args.targets)
		scanner = UniScanner('SMBScanner', [executor], [tgen], worker_count=args.worker_count, host_timeout=args.timeout)
		await scanner.scan_and_process(progress=not args.no_progress, out_file=args.out_file, include_errors=args.errors)
		return
	
	if args.scantype == 'interface':
		connectionfactory = SMBConnectionFactory.from_url(args.url)
		executor = smbscan_options[args.scantype][0](connectionfactory)
		tgen = UniTargetGen.from_list(args.targets)
		scanner = UniScanner('SMBScanner', [executor], [tgen], worker_count=args.worker_count, host_timeout=args.timeout)
		await scanner.scan_and_process(progress=not args.no_progress, out_file=args.out_file, include_errors=args.errors)
		return
	
	if args.scantype == 'proto':
		connectionfactory = SMBConnectionFactory.create_dummy()
		executor = smbscan_options[args.scantype][0](connectionfactory)
		tgen = UniTargetGen.from_list(args.targets)
		scanner = UniScanner('SMBScanner', [executor], [tgen], worker_count=args.worker_count, host_timeout=args.timeout)
		await scanner.scan_and_process(progress=not args.no_progress, out_file=args.out_file, include_errors=args.errors)
		return

	if args.scantype == 'encryption':
		connectionfactory = SMBConnectionFactory.from_url(args.url)
		executor = smbscan_options[args.scantype][0](connectionfactory)
		tgen = UniTargetGen.from_list(args.targets)
		scanner = UniScanner('SMBScanner', [executor], [tgen], worker_count=args.worker_count, host_timeout=args.timeout)
		await scanner.scan_and_process(progress=not args.no_progress, out_file=args.out_file, include_errors=args.errors)
		return
	
	if args.scantype == 'admin':
		connectionfactory = SMBConnectionFactory.from_url(args.url)
		executor = smbscan_options[args.scantype][0](connectionfactory)
		tgen = UniTargetGen.from_list(args.targets)
		scanner = UniScanner('SMBScanner', [executor], [tgen], worker_count=args.worker_count, host_timeout=args.timeout)
		await scanner.scan_and_process(progress=not args.no_progress, out_file=args.out_file, include_errors=args.errors)
		return
	
	if args.scantype in ['session','regsession']:
		connectionfactory = SMBConnectionFactory.from_url(args.url)
		executor = smbscan_options[args.scantype][0](connectionfactory)
		tgen = UniTargetGen.from_list(args.targets)
		scanner = UniScanner('SMBScanner', [executor], [tgen], worker_count=args.worker_count, host_timeout=args.timeout)
		await scanner.scan_and_process(progress=not args.no_progress, out_file=args.out_file, include_errors=args.errors)
		return
	
	if args.scantype == 'printnightmare':
		connectionfactory = SMBConnectionFactory.from_url(args.url)
		executor = smbscan_options[args.scantype][0](connectionfactory)
		tgen = UniTargetGen.from_list(args.targets)
		scanner = UniScanner('SMBScanner', [executor], [tgen], worker_count=args.worker_count, host_timeout=args.timeout)
		await scanner.scan_and_process(progress=not args.no_progress, out_file=args.out_file, include_errors=args.errors)
		return
	
	if args.scantype == 'file':
		connectionfactory = SMBConnectionFactory.from_url(args.url)
		executor = smbscan_options[args.scantype][0](connectionfactory, depth=args.depth)
		tgen = UniTargetGen.from_list(args.targets)
		scanner = UniScanner('SMBScanner', [executor], [tgen], worker_count=args.worker_count, host_timeout=None)
		await scanner.scan_and_process(progress=not args.no_progress, out_file=args.out_file, include_errors=args.errors)
		return
	
	if args.scantype == 'brute':
		target = SMBTarget(ip = args.target, domain = args.domain, proxies = None)

		exclude_users = {}
		executor = smbscan_options[args.scantype][0](target, exclude_users)
		cgen = UniCredentialGen(max_attempts=args.max_attempts, sleep_time=args.sleep_time, domain=args.domain, username_is_password=args.up)
		try:
			cgen.add_users_file(args.usernames)
		except:
			cgen.add_username(args.usernames)
		
		if not args.up:
			cgen.add_passwords_file(args.passwords)
		scanner = UniScanner('SMBScanner', executor, [cgen], worker_count=args.worker_count, host_timeout=None)
		await scanner.scan_and_process(progress=not args.no_progress, out_file=args.out_file, include_errors=args.errors)
		return
	
	if args.scantype == 'share':
		connectionfactory = SMBConnectionFactory.from_url(args.url)
		executor = smbscan_options[args.scantype][0](connectionfactory, test_write=args.write_test, fetch_share_sd=args.share_sd)
		tgen = UniTargetGen.from_list(args.targets)
		scanner = UniScanner('SMBScanner', [executor], [tgen], worker_count=args.worker_count, host_timeout=None)
		await scanner.scan_and_process(progress=not args.no_progress, out_file=args.out_file, include_errors=args.errors)
		return

def main(argv=None):
	asyncio.run(amain(argv))

if __name__ == '__main__':
	main()