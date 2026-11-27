
import asyncio
import logging

from aiosmb.commons.connection.factory import SMBConnectionFactory
from aiosmb import logger
from aiosmb.examples._cli import (
	CONNECTION_EPILOG,
	add_url_help,
	add_verbosity,
	make_parser,
)

import tqdm

async def amain(url, outfilename, progress = True):
	smburl = SMBConnectionFactory.from_url(url)
	connection = smburl.get_connection()
	smbfile = smburl.get_file()

	async with connection:
		_, err = await connection.login()
		if err is not None:
			raise err
		
		_, err = await smbfile.open(connection)
		if err is not None:
			raise err

		if outfilename is None:
			outfilename = smbfile.name
		
		if progress is True:
			pbar = tqdm.tqdm(desc = 'Downloading %s' % outfilename, total=smbfile.size, unit='B', unit_scale=True, unit_divisor=1024)
		
		with open(outfilename, 'wb') as outfile:
			async for data, err in smbfile.read_chunked():
				if err is not None:
					raise err
				if data is None:
					break
				outfile.write(data)
				if progress is True:
					pbar.update(len(data))

def build_parser(prog=None):
	parser = make_parser(
		'Download one file from an SMB share',
		prog=prog,
		epilog=CONNECTION_EPILOG,
	)
	add_url_help(parser)

	output = parser.add_argument_group('output')
	output.add_argument(
		'-o',
		'--out-file',
		metavar='PATH',
		help='local output path; defaults to the remote file name',
	)
	output.add_argument(
		'--progress',
		action='store_true',
		help='show a byte progress bar',
	)
	add_verbosity(output)

	parser.add_argument(
		'url',
		metavar='URL',
		help=(
			'SMB connection URL including /share/path/to/file; '
			'use --help-url for the complete format'
		),
	)
	return parser


def main(argv=None):
	parser = build_parser()
	args = parser.parse_args(argv)

	if args.verbose >=1:
		logger.setLevel(logging.DEBUG)

	if args.verbose > 2:
		print('setting deepdebug')
		logger.setLevel(1) #enabling deep debug
		asyncio.get_event_loop().set_debug(True)
		logging.basicConfig(level=logging.DEBUG)

	
	asyncio.run(amain(args.url, args.out_file, args.progress))

if __name__ == '__main__':
	main()