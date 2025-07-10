
import logging
import tqdm
from aiosmb import logger
import uuid
import asyncio
import zipfile
import tempfile
import os
from pathlib import PureWindowsPath
import datetime
from aiosmb.commons.connection.factory import SMBConnectionFactory
from aiosmb.commons.interfaces.file import SMBFile


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



class SMBGET:
	def __init__(self, smb_url, show_progress = False):
		self.smb_mgr = SMBConnectionFactory.from_url(smb_url)
		self.target_gens = []
		self.task_q = None
		self.__total_targets = 0
		self.target_gen_task = None
		self.show_progress = show_progress

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

			zip_file_path = f'output_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.zip'
			with zipfile.ZipFile(zip_file_path, 'w') as zip_file:
				while True:
					t = await self.task_q.get()
					if t is None:
						return True, None
				
					tid, target = t
					unc = PureWindowsPath(target)
					file_name = unc.name

					connection = self.smb_mgr.create_connection_newtarget(target.replace('\\\\','').split('\\')[0])
					async with connection:
						_, err = await connection.login()
						if err is not None:
							raise err
						
						smbfile = SMBFile.from_uncpath(target)
						_, err = await smbfile.open(connection, 'r')
						if err is not None:
							logger.info('Error Downloading file %s' % target)
							continue
						
						if self.show_progress is True:
							pbar = tqdm.tqdm(desc = 'Downloading %s' % file_name, total=smbfile.size, unit='B', unit_scale=True, unit_divisor=1024)
						
						# create a temp binary write
						temp_file = tempfile.NamedTemporaryFile(delete=False)
						temp_file_path = temp_file.name
						try:
							with open(temp_file_path, 'wb') as f:
								async for data, err in smbfile.read_chunked():
									if err is not None:
										logger.info('Error Downloading file %s' % target)
										continue
									if data is None:
										break

									f.write(data)

									if self.show_progress is True:
										pbar.update(len(data))

							zip_file.write(temp_file_path, target)
						finally:
							os.remove(temp_file_path)


			return True, None
		except Exception as e:
			return False, e


async def amain():
	import argparse
	import sys

	parser = argparse.ArgumentParser(description='SMB Share enumerator')
	parser.add_argument('-v', '--verbose', action='count', default=0)
	parser.add_argument('-s', '--stdin', action='store_true', help='Read targets from stdin')
	parser.add_argument('--progress', action='store_true', help='Show progress')
	parser.add_argument('url', help='Connection URL base, target can be set to anything. Owerrides all parameter based connection settings! Example: "smb2+ntlm-password://TEST\\victim@test"')
	parser.add_argument('targets', nargs='*', help = 'UNC paths of file eg. \\\\HOST\\SHARE\\file_or_folder')
	args = parser.parse_args()

	if args.verbose >=1:
		logger.setLevel(logging.DEBUG)

	if args.verbose > 2:
		print('setting deepdebug')
		logger.setLevel(1) #enabling deep debug
		asyncio.get_event_loop().set_debug(True)
		logging.basicConfig(level=logging.DEBUG)

	smb_url = args.smb_url	
	smbget = SMBGET(smb_url, show_progress=args.progress)
	
	notfile = []
	if len(args.targets) == 0 and args.stdin is True:
		smbget.target_gens.append(ListTargetGen(sys.stdin))
	else:
		for target in args.targets:
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
		
	await smbget.run()

def main():
	asyncio.run(amain())

if __name__ == '__main__':
	main()