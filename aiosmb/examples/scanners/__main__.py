
import asyncio
import logging
from aiosmb.commons.connection.factory import SMBConnectionFactory
from aiosmb.examples.scanners.smbfinger import SMBFingerScanner
from aiosmb.examples.scanners.smbiface import SMBInterfaceScanner
from aiosmb.examples.scanners.smbproto import SMBProtocolScanner
from aiosmb.examples.scanners.smbadmin import SMBAdminScanner
from aiosmb.examples.scanners.smbsession import SMBSessionScanner
from aiosmb.examples.scanners.smbprintnightmare import SMBPrintnightmareScanner
from aiosmb.examples.scanners.smbfile import SMBFileScanner

smbscan_options = {
	'finger'    : (SMBFingerScanner, "SMB Finger grabs OS info. Only works with NTLM auth"),
	'interface' : (SMBInterfaceScanner, "Lists available interfaces on the remote hosts"),
	'scantype'  : (SMBProtocolScanner, "SMB protocol version and NTLM signing checker"),
	'admin'     : (SMBAdminScanner, "Checks if giver user is admin on the remote hosts"),
	'session'   : (SMBSessionScanner, "Lists SMB sessions"),
	'printnightmare': (SMBPrintnightmareScanner, "Checks hosts for printnightmare vulnerability"),
	'file' : (SMBFileScanner, 'Enumerates files and shares')
}

async def amain():
	import argparse
	from asysocks.unicomm.common.scanner.targetgen import UniTargetGen
	from asysocks.unicomm.common.scanner.scanner import UniScanner
	from aiosmb import logger

	scannertpes_usage = '\r\nall: Runs all scanners\r\n'
	for k in smbscan_options:
		scannertpes_usage += '%s: %s\r\n' % (k, smbscan_options[k][1])
	usage = """
Scanner types (-s param):
	%s
"""% (scannertpes_usage,)

	parser = argparse.ArgumentParser(description='SMB Scanner', usage=usage)
	parser.add_argument('-w', '--worker-count', type=int, default=100, help='Parallell count')
	parser.add_argument('-t', '--timeout', type=int, default=10, help='Timeout for each connection')
	parser.add_argument('--no-progress', action='store_false', help='Disable progress bar')
	parser.add_argument('-o', '--out-file', help='Output file path.')
	parser.add_argument('-s', '--scan', nargs='+', required=True, help='Scanner type')
	parser.add_argument('-e', '--errors', action='store_true', help='Includes errors in output.')
	parser.add_argument('url', help = 'Connection string in URL format')
	parser.add_argument('targets', nargs='*', help = 'Hostname or IP address or file with a list of targets')
	args = parser.parse_args()

	if len(args.targets) == 0:
		print('No targets defined!')
		return
	
	logger.setLevel(logging.CRITICAL)
	
	connectionfactory = SMBConnectionFactory.from_url(args.url)
	scantypes = []
	for x in args.scan:
		scantypes.append(x.lower())
	executors = []
	if 'all' in scantypes:
		for k in smbscan_options:
			executors.append(smbscan_options[k][0](connectionfactory))
	else:
		for scantype in scantypes:
			if scantype not in smbscan_options:
				print('Unknown scan type: "%s"' % scantype)
				return
			executors.append(smbscan_options[scantype][0](connectionfactory))
			
	timeout = args.timeout
	if 'file' in scantypes:
		timeout = None
		
	tgen = UniTargetGen.from_list(args.targets)
	scanner = UniScanner('SMBScanner', executors, [tgen], worker_count=args.worker_count, host_timeout=timeout)
	await scanner.scan_and_process(progress=args.no_progress, out_file=args.out_file, include_errors=args.errors)

def main():
	asyncio.run(amain())

if __name__ == '__main__':
	main()