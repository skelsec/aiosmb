
import asyncio
import enum
import uuid
import logging

from aiosmb import logger
from aiosmb.commons.connection.url import SMBConnectionURL
from aiosmb.commons.interfaces.machine import SMBMachine

from tqdm import tqdm

# https://stackoverflow.com/questions/1094841/get-human-readable-version-of-file-size
def sizeof_fmt(num, suffix='B'):
	if num is None:
		return ''
	for unit in ['','Ki','Mi','Gi','Ti','Pi','Ei','Zi']:
		if abs(num) < 1024.0:
			return "%3.1f%s%s" % (num, unit, suffix)
		num /= 1024.0
	return "%.1f%s%s" % (num, 'Yi', suffix)

class EnumResultStatus(enum.Enum):
	RESULT = 'RESULT'
	FINISHED = 'FINISED'
	ERROR = 'ERROR'

class EnumResult:
	def __init__(self, target_id, target, result, error = None, status = EnumResultStatus.RESULT):
		self.target_id = target_id
		self.target = target
		self.error = error
		self.result = result
		self.status = status

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


class SMBFileEnum:
	def __init__(self, smb_url, worker_count = 10, depth = 3, enum_url = True, out_file = None, show_pbar = True, max_items = None, max_runtime = 60):
		self.target_gens = []
		self.smb_mgr = SMBConnectionURL(smb_url)
		self.worker_count = worker_count
		self.task_q = None
		self.res_q = None
		self.depth = depth
		self.workers = []
		self.result_processing_task = None
		self.enum_url = enum_url
		self.out_file = out_file
		self.show_pbar = show_pbar
		self.max_items = max_items
		self.max_runtime = max_runtime
		self.__gens_finished = False
		self.__total_targets = 0
		self.__total_finished = 0

		self.__total_size = 0
		self.__total_shares = 0
		self.__total_dirs = 0
		self.__total_files = 0
		self.__total_errors = 0
		self.__current_targets = {}

	async def __executor(self, tid, target):
		try:
			connection = self.smb_mgr.create_connection_newtarget(target)
			async with connection:
				_, err = await connection.login()
				if err is not None:
					raise err

				machine = SMBMachine(connection)
				async for obj, otype, err in machine.enum_all_recursively(depth = self.depth, maxentries = self.max_items):
					er = EnumResult(tid, target, (obj, otype, err))
					await self.res_q.put(er)

		except asyncio.CancelledError:
			return
		except Exception as e:
			await self.res_q.put(EnumResult(tid, target, None, error = e, status = EnumResultStatus.ERROR))
		finally:
			await self.res_q.put(EnumResult(tid, target, None, status = EnumResultStatus.FINISHED))

	async def worker(self):
		try:
			while True:
				indata = await self.task_q.get()
				if indata is None:
					return
				
				tid, target = indata
				try:
					await asyncio.wait_for(self.__executor(tid, target), timeout=self.max_runtime)
				except asyncio.CancelledError:
					return
				except asyncio.TimeoutError as e:
					await self.res_q.put(EnumResult(tid, target, None, error = e, status = EnumResultStatus.ERROR))
					await self.res_q.put(EnumResult(tid, target, None, status = EnumResultStatus.FINISHED))
					continue
				except Exception as e:
					logger.exception('worker')
					continue
		except asyncio.CancelledError:
			return
				
		except Exception as e:
			return e

	async def result_processing(self):
		try:
			pbar = None
			if self.show_pbar is True:
				pbar = {}
				pbar['targets'] = tqdm(desc='Targets     ', position=0)
				pbar['shares']  = tqdm(desc='Shares      ', position=1)
				pbar['dirs']    = tqdm(desc='Dirs        ', position=2)
				pbar['files']   = tqdm(desc='Files       ', position=3)
				pbar['filesize']= tqdm(desc='Files (size)', unit='B', unit_scale=True, position=4)
				pbar['maxed']   = tqdm(desc='Maxed       ', position=5)
				pbar['errors']  = tqdm(desc='Errors      ', position=6)

			out_buffer = []
			final_iter = False
			while True:
				try:
					if len(out_buffer) >= 10000 or final_iter:
						out_data = '\r\n'.join(out_buffer)
						out_buffer = []
						if self.out_file is not None:
							with open(self.out_file, 'a+', newline = '') as f:
								f.write(out_data)
						else:
							print(out_data)
						
						if self.show_pbar is True:
							for key in pbar:
								pbar[key].refresh()

					if final_iter:
						asyncio.create_task(self.terminate())
						return
					try:
						er = await asyncio.wait_for(self.res_q.get(), timeout = 5)
					except asyncio.TimeoutError:
						if self.show_pbar is True:
							for key in pbar:
								pbar[key].refresh()

						if self.__total_finished == self.__total_targets and self.__gens_finished is True:
							final_iter = True
						continue

					
					if er.status == EnumResultStatus.FINISHED:
						self.__total_finished += 1
						if self.show_pbar is True:
							pbar['targets'].update(1)

						out_buffer.append('[P][%s/%s][%s]' % (self.__total_targets, self.__total_finished, str(self.__gens_finished)))
						if self.__total_finished == self.__total_targets and self.__gens_finished is True:
							final_iter = True
							continue
							
					if er.result is not None:
						obj, otype, err = er.result
						if otype is not None:
							if otype == 'file':
								out_buffer.append('[%s] %s | %s | %s | %s' % (otype[0].upper(), obj.unc_path, obj.creation_time, obj.size, sizeof_fmt(obj.size)))
								self.__total_files += 1
								if isinstance(obj.size, int) is True: #just making sure...
									self.__total_size += obj.size
									if self.show_pbar is True:
										pbar['filesize'].update(obj.size)
							elif otype == 'dir':
								out_buffer.append('[%s] %s | %s' % (otype[0].upper(), obj.unc_path, obj.creation_time))
								self.__total_dirs += 1
							elif otype == 'share':
								out_buffer.append('[%s] %s' % (otype[0].upper(), obj.unc_path))
								self.__total_shares += 1
							else:
								out_buffer.append('[%s] %s' % (otype[0].upper(), obj.unc_path))
							
							if self.show_pbar is True:
								if otype == 'dir':
									pbar['dirs'].update(1)
								elif otype == 'file':
									pbar['files'].update(1)
								elif otype == 'share':
									pbar['shares'].update(1)
								elif otype == 'maxed':
									pbar['maxed'].update(1)

						if err is not None:
							out_buffer.append('[E] %s %s' % (err, obj.unc_path))
							self.__total_errors += 1
							if self.show_pbar is True:
								pbar['errors'].update(1)
				except asyncio.CancelledError:
					return
				except Exception as e:
					logger.exception('result_processing inner')
					asyncio.create_task(self.terminate())
					return
		except asyncio.CancelledError:
			return
		except Exception as e:
			logger.exception('result_processing')
			asyncio.create_task(self.terminate())

	async def terminate(self):
		for worker in self.workers:
			worker.cancel()
		if self.result_processing_task is not None:
			self.result_processing_task.cancel()		

	async def setup(self):
		try:
			if self.res_q is None:
				self.res_q = asyncio.Queue() #self.worker_count
				self.result_processing_task = asyncio.create_task(self.result_processing())
			if self.task_q is None:
				self.task_q = asyncio.Queue()

			for _ in range(self.worker_count):
				self.workers.append(asyncio.create_task(self.worker()))

			return True, None
		except Exception as e:
			return None, e
	
	async def run(self):
		try:
			_, err = await self.setup()
			if err is not None:
				raise err
			
			if self.enum_url is True:
				self.__total_targets += 1
				await self.task_q.put((str(uuid.uuid4()), self.smb_mgr.get_target().get_hostname_or_ip()))
			
			for target_gen in self.target_gens:
				total, err = await target_gen.run(self.task_q)
				self.__total_targets += total
				if err is not None:
					print('Target gen error! %s' % err)

			self.__gens_finished = True
			
			await asyncio.gather(*self.workers)
			await self.result_processing_task
			return True, None
		except Exception as e:
			print(e)
			return None, e

async def amain():
	import argparse
	import sys
	from aiosmb.commons.connection.params import SMBConnectionParams

	epilog = """
Output legend:
    [S] Share
    [D] Dictionary
    [F] File
    [E] Error
    [M] Maxed (max items limit reached for directory)
    [P] Progress (current/total)
"""

	parser = argparse.ArgumentParser(description='SMB Share enumerator', formatter_class=argparse.RawDescriptionHelpFormatter, epilog=epilog)
	SMBConnectionParams.extend_parser(parser)
	parser.add_argument('-v', '--verbose', action='count', default=0)
	parser.add_argument('--depth', type=int, default=3, help='Recursion depth, -1 means infinite')
	parser.add_argument('-w', '--smb-worker-count', type=int, default=100, help='Parallell count')
	parser.add_argument('-o', '--out-file', help='Output file path.')
	parser.add_argument('-s', '--stdin', action='store_true', help='Read targets from stdin')
	parser.add_argument('-m', '--max-items', type = int, default=None, help='Stop enumeration of a directory after M items were discovered.')
	parser.add_argument('--url', help='Connection URL base, target can be set to anything. Owerrides all parameter based connection settings! Example: "smb2+ntlm-password://TEST\\victim@test"')
	parser.add_argument('targets', nargs='*', help = 'Hostname or IP address or file with a list of targets')
	parser.add_argument('--progress', action='store_true', help='Show progress bar')
	args = parser.parse_args()

	if args.verbose >=1:
		logger.setLevel(logging.DEBUG)

	if args.verbose > 2:
		print('setting deepdebug')
		logger.setLevel(1) #enabling deep debug
		asyncio.get_event_loop().set_debug(True)
		logging.basicConfig(level=logging.DEBUG)

	smb_url = None
	if args.url is not None:
		smb_url = args.url
	else:
		try:
			smb_url = SMBConnectionParams.parse_args(args)
		except Exception as e:
			print('Either URL or all connection parameters must be set! Error: %s' % str(e))
			sys.exit(1)
	
	enumerator = SMBFileEnum(smb_url, worker_count = args.smb_worker_count, depth = args.depth, out_file = args.out_file, show_pbar = args.progress, max_items = args.max_items)
	
	notfile = []
	if len(args.targets) == 0 and args.stdin is True:
		enumerator.target_gens.append(ListTargetGen(sys.stdin))
	else:
		for target in args.targets:
			try:
				f = open(target, 'r')
				f.close()
				enumerator.target_gens.append(FileTargetGen(target))
			except:
				notfile.append(target)
	
	if len(notfile) > 0:
		enumerator.target_gens.append(ListTargetGen(notfile))

	if len(enumerator.target_gens) == 0:
		print('[-] No suitable targets were found!')
		return
		
	await enumerator.run()

def main():
	asyncio.run(amain())

if __name__ == '__main__':
	main()