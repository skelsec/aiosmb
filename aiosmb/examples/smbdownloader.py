
import logging
import tqdm
import datetime
import traceback
import re
import sys
from aiosmb import logger
import uuid
import asyncio
from pathlib import PureWindowsPath
from typing import List

from aiosmb.commons.connection.factory import SMBConnectionFactory
from aiosmb.commons.interfaces.file import SMBFile

def convert_size(size_str):
    # Dictionary to convert units to their corresponding byte values
    units = {
        'B': 1,
        'K': 1024,
        'KB': 1024,
        'M': 1024 ** 2,
        'MB': 1024 ** 2,
        'G': 1024 ** 3,
        'GB': 1024 ** 3,
        'T': 1024 ** 4,
        'TB': 1024 ** 4,
        'P': 1024 ** 5,
        'PB': 1024 ** 5,
        'E': 1024 ** 6,
        'EB': 1024 ** 6,
        'Z': 1024 ** 7,
        'ZB': 1024 ** 7,
        'Y': 1024 ** 8,
        'YB': 1024 ** 8,
    }
    
    # Regex to capture the numeric part and the unit part
    match = re.match(r'^\s*([\d\.]+)\s*([KMGTPEZY]?B?)\s*$', size_str.strip(), re.IGNORECASE)
    
    if not match:
        raise ValueError(f"Invalid size format: {size_str}")
    
    number, unit = match.groups()
    number = float(number)
    unit = unit.upper()
    
    # Convert the number to bytes
    return int(number * units[unit])

def flatten_unc_path_to_filename(unc_path, max_length=255):
    # Replace backslashes with underscores
    filename = unc_path.replace("\\", "_").replace("/", "_")
    
    # Replace characters that are invalid in filenames with underscores
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    
    # Replace any remaining whitespace characters with underscores
    filename = re.sub(r'\s+', '_', filename)
    
    # If the filename is longer than the maximum length, truncate it from the beginning
    if len(filename) > max_length:
        filename = filename[-max_length:]
    
    return filename


class FileTargetGen:
	def __init__(self, filename):
		self.filename = filename

	async def run(self, target_q):
		try:
			cnt = 0
			with open(self.filename, 'r') as f:
				for line in f:
					line = line.strip()
					if line == '':
						continue
					await target_q.put((str(uuid.uuid4()), line))
					await asyncio.sleep(0)
					cnt += 1
			return cnt, None
		except Exception as e:
			return cnt, e

class ListTargetGen:
	def __init__(self, targets):
		self.targets = targets

	async def run(self, target_q):
		try:
			cnt = 0
			for target in self.targets:
				cnt += 1
				target = target.strip()
				await target_q.put((str(uuid.uuid4()),target))
				await asyncio.sleep(0)
			return cnt, None
		except Exception as e:
			return cnt, e



class SMBDownloader:
	def __init__(self, smb_url, show_progress = False, flat_names = True, max_fsize = 1024*1024, store_errors = False, silent = False):
		self.smb_mgr = SMBConnectionFactory.from_url(smb_url)
		self.target_gens = []
		self.__skip_targets = {}
		self.task_q = None
		self.__total_targets = 0
		self.__error_filename = 'smbget_errors_%s.txt' % datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
		self.target_gen_task = None
		self.show_progress = show_progress
		self.flat_names = flat_names
		self.max_fsize = max_fsize
		self.store_errors = store_errors
		self.silent = silent
	
	def __write_error(self, target_address, target, exc:Exception):
		errorstr = 'Target: %s\r\nError: %s\r\n' % (target, str(exc))
		errorstr += ''.join(traceback.format_tb(exc.__traceback__))

		if self.store_errors is False:
			if self.silent is False:
				print(errorstr)
			return
		
		with open(self.__error_filename, 'a') as f:
			f.write(errorstr + '\r\n')


	async def __target_gen(self):
		for target_gen in self.target_gens:
			total, err = await target_gen.run(self.task_q)
			self.__total_targets += total
			if err is not None:
				print('Target gen error! %s' % err)
			await self.task_q.put(None)

	async def run(self):
		try:
			self.task_q = asyncio.Queue()
			self.target_gen_task = asyncio.create_task(self.__target_gen())

			while True:
				t = await self.task_q.get()
				if t is None:
					return True, None
				
				tid, target = t
				file_name = PureWindowsPath(target).name
				if self.flat_names is True:
					file_name = flatten_unc_path_to_filename("%s_%s" % (tid, target))
				
				target_address = target.replace('\\\\','').split('\\')[0]
				if target_address in self.__skip_targets:
					continue

				connection = self.smb_mgr.create_connection_newtarget(target_address)
				async with connection:
					_, err = await connection.login()
					if err is not None:
						self.__skip_targets[target_address] = err
						self.__write_error(target_address, target, err)
					
					smbfile = SMBFile.from_uncpath(target)
					_, err = await smbfile.open(connection, 'r')
					if err is not None:
						self.__write_error(target_address, target, err)
						continue

					if smbfile.size > self.max_fsize:
						if self.silent is False:
							print('File %s is too large, skipping!' % target)
						continue
					
					if self.show_progress is True:
						pbar = tqdm.tqdm(desc = 'Downloading %s' % target, total=smbfile.size, unit='B', unit_scale=True, unit_divisor=1024)
					else:
						if self.silent is False:
							print('Downloading %s' % target)
					
					with open(file_name, 'wb') as f:
						async for data, err in smbfile.read_chunked():
							if err is not None:
								self.__write_error(target_address, target, err)
								continue
							if data is None:
								break

							f.write(data)

							if self.show_progress is True:
								pbar.update(len(data))

			return True, None
		except Exception as e:
			return False, e

async def smbdownloader(smb_url, targets:List[str], from_stdin:bool, verbose:int = 0, show_progress:bool = False, flat_names:bool = True, max_fsize:int or str = 1024*1024, store_errors:bool = False, silent:bool=False):
	if verbose >=1:
		logger.setLevel(logging.DEBUG)

	if verbose > 2:
		logger.setLevel(1) #enabling deep debug
		asyncio.get_event_loop().set_debug(True)
		logging.basicConfig(level=logging.DEBUG)
	
	max_fsize = convert_size(max_fsize)
	
	smbget = SMBDownloader(smb_url, show_progress=show_progress, flat_names = flat_names, max_fsize = max_fsize, store_errors = store_errors, silent=silent)
	
	notfile = []
	if len(targets) == 0 and from_stdin is True:
		smbget.target_gens.append(ListTargetGen(sys.stdin))
	else:
		for target in targets:
			try:
				f = open(target, 'r')
				f.close()
				smbget.target_gens.append(FileTargetGen(target))
			except:
				notfile.append(target)
	
	if len(notfile) > 0:
		smbget.target_gens.append(ListTargetGen(notfile))

	if len(smbget.target_gens) == 0:
		print('[-] No suitable targets were found!')
		return
		
	return await smbget.run()

async def amain():
	import argparse

	parser = argparse.ArgumentParser(description='SMB File downloader')
	parser.add_argument('-v', '--verbose', action='count', default=0)
	parser.add_argument('-s', '--stdin', action='store_true', help='Read targets from stdin')
	parser.add_argument('-e', '--store-errors', action='store_true', help='Store errors in a file')
	parser.add_argument('--silent', action='store_true', help='Do not show any output')
	parser.add_argument('--no-flat-names', action='store_true', help='Do not flatten file names. This will keep the original file name, but will overwrite files with the same name.')
	parser.add_argument('--progress', action='store_true', help='Show progress')
	parser.add_argument('--max-size', type=str, default='1M', help='Maximum length of the flattened file name. Default is 1 MB.')
	parser.add_argument('url', help='Connection URL base, target can be set to anything. Example: "smb2+ntlm-password://TEST\\victim@test"')
	parser.add_argument('targets', nargs='*', help = 'UNC paths of file eg. \\\\HOST\\SHARE\\file_or_folder')
	args = parser.parse_args()

	_, err = await smbdownloader(args.url, args.targets, args.stdin, args.verbose, args.progress, not args.no_flat_names, args.max_size, args.store_errors, args.silent)
	if err is not None:
		print('[-] Error! %s' % err)
		sys.exit(1)
	sys.exit(0)


def main():
	asyncio.run(amain())

if __name__ == '__main__':
	main()