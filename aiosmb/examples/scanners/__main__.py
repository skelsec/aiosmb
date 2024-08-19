
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

smbscan_options = {
	'finger'    : (SMBFingerScanner, "SMB Finger grabs OS info. Only works with NTLM auth"),
	'interface' : (SMBInterfaceScanner, "Lists available interfaces on the remote hosts"),
	'proto'  : (SMBProtocolScanner, "SMB protocol version and NTLM signing checker"),
	'admin'     : (SMBAdminScanner, "Checks if giver user is admin on the remote hosts"),
	'session'   : (SMBSessionScanner, "Lists SMB sessions"),
	'printnightmare': (SMBPrintnightmareScanner, "Checks hosts for printnightmare vulnerability"),
	'file' : (SMBFileScanner, 'Enumerates files and shares'),
	'brute'	 : (SMBBruteForceScanner, "Brute forces SMB logins")
}

async def amain():
	import argparse
	from asysocks.unicomm.common.scanner.targetgen import UniTargetGen, UniCredentialGen
	from asysocks.unicomm.common.scanner.scanner import UniScanner
	from aiosmb import logger

	parser = argparse.ArgumentParser(description='SMB Scanner')
	parser.add_argument('-w', '--worker-count', type=int, default=100, help='Parallell count')
	parser.add_argument('-t', '--timeout', type=int, default=10, help='Timeout for each connection')
	parser.add_argument('--no-progress', action='store_false', help='Disable progress bar')
	parser.add_argument('-o', '--out-file', help='Output file path.')
	parser.add_argument('-e', '--errors', action='store_true', help='Includes errors in output.')
	parser.add_argument('-d', '--depth', type=int, default=6, help='Share enumeration depth.')
	subparsers = parser.add_subparsers(title="scantype", dest="scantype", required=True)
	
	fingerscan = subparsers.add_parser('finger', help='Fetch certificate')
	fingerscan.add_argument('targets', nargs='*', help = 'Hostname or IP address or file with a list of targets')
	
	interfacescan = subparsers.add_parser('interface', help='List interfaces')
	interfacescan.add_argument('url', help = 'Connection string in URL format')
	interfacescan.add_argument('targets', nargs='*', help = 'Hostname or IP address or file with a list of targets')

	protoscan = subparsers.add_parser('proto', help='Scan for SMB protocol version and NTLM signing')
	protoscan.add_argument('targets', nargs='*', help = 'Hostname or IP address or file with a list of targets')

	adminscan = subparsers.add_parser('admin', help='Check if user is admin')
	adminscan.add_argument('url', help = 'Connection string in URL format')
	adminscan.add_argument('targets', nargs='*', help = 'Hostname or IP address or file with a list of targets')

	sessionscan = subparsers.add_parser('session', help='List SMB sessions')
	sessionscan.add_argument('url', help = 'Connection string in URL format')
	sessionscan.add_argument('targets', nargs='*', help = 'Hostname or IP address or file with a list of targets')

	printnightmarescan = subparsers.add_parser('printnightmare', help='Check for printnightmare vulnerability')
	printnightmarescan.add_argument('url', help = 'Connection string in URL format')
	printnightmarescan.add_argument('targets', nargs='*', help = 'Hostname or IP address or file with a list of targets')

	filescan = subparsers.add_parser('file', help='Enumerate files and shares')
	filescan.add_argument('url', help = 'Connection string in URL format')
	filescan.add_argument('targets', nargs='*', help = 'Hostname or IP address or file with a list of targets')

	brutescan = subparsers.add_parser('brute', help='Brute force SMB logins')
	brutescan.add_argument('-d', '--domain', help = 'Connection string in URL format')
	brutescan.add_argument('-u', '--usernames', help = 'Connection string in URL format')

	# Create a mutually exclusive group for -p/--passwords and --up
	group = brutescan.add_mutually_exclusive_group(required=True)
	group.add_argument('-p', '--passwords', help='Connection string in URL format')
	group.add_argument('--up', action='store_true', help='Username is password')

	brutescan.add_argument('-s', '--sleep-time', default=5, type=int, help = 'Sleep time between attempts per user')
	brutescan.add_argument('-a', '--max-attempts', default=3, type=int, help = 'Max unsuccessful attempts per user')
	brutescan.add_argument('target', help = 'IP/hostname of target')
	
	args = parser.parse_args()
	
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
	
	if args.scantype == 'admin':
		connectionfactory = SMBConnectionFactory.from_url(args.url)
		executor = smbscan_options[args.scantype][0](connectionfactory)
		tgen = UniTargetGen.from_list(args.targets)
		scanner = UniScanner('SMBScanner', [executor], [tgen], worker_count=args.worker_count, host_timeout=args.timeout)
		await scanner.scan_and_process(progress=not args.no_progress, out_file=args.out_file, include_errors=args.errors)
		return
	
	if args.scantype == 'session':
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

def main():
	asyncio.run(amain())

if __name__ == '__main__':
	main()