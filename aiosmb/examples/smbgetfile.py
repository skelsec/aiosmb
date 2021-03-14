
import asyncio
import logging

from aiosmb.commons.connection.url import SMBConnectionURL
from aiosmb import logger

import tqdm

async def amain(url, outfilename, progress = True):
	smburl = SMBConnectionURL(url)
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

def main():
	import argparse

	parser = argparse.ArgumentParser(description='SMB file downloader')
	parser.add_argument('-v', '--verbose', action='count', default=0)
	#parser.add_argument('-r', '--recursive', action='store_true', help='Recirsively donwload all files from the remote folder')
	parser.add_argument('--progress', action='store_true', help='Show progress')
	parser.add_argument('-o', '--out-file', help='Output file name. Optional.')
	parser.add_argument('url', help='SMB URL with full file path. Example: smb2+ntlm-password://TEST\\Administrator:pw@10.10.10.1/C$/test.txt')
	
	args = parser.parse_args()

	if args.verbose >=1:
		logger.setLevel(logging.DEBUG)

	if args.verbose > 2:
		print('setting deepdebug')
		logger.setLevel(1) #enabling deep debug
		asyncio.get_event_loop().set_debug(True)
		logging.basicConfig(level=logging.DEBUG)

	
	asyncio.run(amain(args.url, args.out_file))

if __name__ == '__main__':
	main()