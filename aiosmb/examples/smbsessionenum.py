
import asyncio
import enum
import uuid
import logging
import json
import ipaddress

from aiosmb import logger
from aiosmb.examples.scancommons.targetgens import *
from aiosmb.examples.scancommons.internal import *
from aiosmb.examples.scancommons.utils import *
from aiosmb.commons.connection.url import SMBConnectionURL
from aiosmb.commons.interfaces.machine import SMBMachine
from aiosmb.commons.utils.univeraljson import UniversalEncoder


from tqdm import tqdm




ENUMRESFINAL_TSV_HDR = ['target', 'target_id', 'username', 'ip_addr', 'err']
class EnumResultFinal:
	def __init__(self, obj, otype, err, target, target_id):
		self.obj = obj
		self.otype = otype
		self.err = err
		self.target = target
		self.target_id = target_id

		self.username = None
		self.ip_addr = None

		if self.otype == 'session':
			self.username = self.obj.username
			self.ip_addr = str(self.obj.ip_addr)


	def __str__(self):
		if self.err is not None:
			return '[E] %s | %s' % (self.unc_path, self.err)

		elif self.otype == 'session':
			return '[S] %s | %s | %s | %s ' % (self.target, self.target_id, self.username, self.ip_addr)

		elif self.otype == 'progress':
			return '[P][%s/%s][%s] %s' % (self.obj.total_targets, self.obj.total_finished, str(self.obj.gens_finished), self.obj.current_finised)

		else:
			return '[UNK]'

	def to_dict(self):
		return {
			'target' : self.target,
			'target_id' : self.target_id,
			'username' : self.username,
			'ip_addr' : self.ip_addr,
			'otype' : self.otype,
			'err' : self.err,
		}
	
	def to_json(self):
		dd = self.to_dict()
		return json.dumps(dd, cls = UniversalEncoder)

	def to_tsv(self, hdrs = ENUMRESFINAL_TSV_HDR):
		if self.otype == 'progress':
			return ''
		dd = self.to_dict()
		data = [ str(dd[x]) for x in hdrs ]
		return '\t'.join(data)


class SMBSessionEnum:
	def __init__(self, smb_url, worker_count = 10, enum_url = False, out_file = None, show_pbar = True, max_items = None, max_runtime = None, task_q = None, res_q = None, output_type = 'str', ext_result_q = None):
		self.target_gens = []
		self.smb_mgr = SMBConnectionURL(smb_url)
		self.worker_count = worker_count
		self.task_q = task_q
		self.res_q = res_q
		self.workers = []
		self.result_processing_task = None
		self.enum_url = enum_url
		self.out_file = out_file
		self.show_pbar = show_pbar
		self.max_items = max_items
		self.max_runtime = max_runtime
		self.output_type = output_type
		self.ext_result_q = ext_result_q
		self.write_buffer_size = 1000

		self.__gens_finished = False
		self.__total_targets = 0
		self.__total_finished = 0
		self.__total_errors = 0

		self.__total_sessions = 0
		self.__current_targets = {}

	async def __executor(self, tid, target):
		try:
			connection = self.smb_mgr.create_connection_newtarget(target)
			async with connection:
				_, err = await connection.login()
				if err is not None:
					raise err

				machine = SMBMachine(connection)
				async for session, err in machine.list_sessions():
					# SMBUserSession
					if err is not None:
						raise err
					er = EnumResult(tid, target, session)
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
				pbar['targets']    = tqdm(desc='Targets     ', unit='', position=0)
				pbar['sessions']   = tqdm(desc='Sessions    ', unit='', position=1)
				pbar['connerrors'] = tqdm(desc='Conn Errors ', unit='', position=2)

			out_buffer = []
			final_iter = False
			while True:
				try:
					if self.__gens_finished is True and self.show_pbar is True and pbar['targets'].total is None:
						pbar['targets'].total = self.__total_targets
						for key in pbar:
							pbar[key].refresh()

					if self.ext_result_q is not None:
						out_buffer = []

					if len(out_buffer) >= self.write_buffer_size or final_iter and self.ext_result_q is None:
						out_data = ''
						if self.output_type == 'str':
							out_data = '\r\n'.join([str(x) for x in out_buffer])
						elif self.output_type == 'tsv':
							for res in out_buffer:
								x = res.to_tsv()
								if x == '':
									continue
								out_data += '%s\r\n' % x
						elif self.output_type == 'json':
							for res in out_buffer:
								out_data += '%s\r\n' % res.to_json()
						else:
							out_data = '\r\n'.join(out_buffer)

						if self.out_file is not None:
							with open(self.out_file, 'a+', newline = '') as f:
								f.write(out_data)
						
						else:
							print(out_data)
						
						if self.show_pbar is True:
							for key in pbar:
								pbar[key].refresh()
						
						out_buffer = []
						out_data = ''

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

						obj = EnumProgress(self.__total_targets, self.__total_finished, self.__gens_finished, er.target)
						if self.ext_result_q is not None:
							await self.ext_result_q.put(EnumResultFinal(obj, 'progress', None, er.target, er.target_id))
						out_buffer.append(EnumResultFinal(obj, 'progress', None, er.target, er.target_id))
						if self.__total_finished == self.__total_targets and self.__gens_finished is True:
							final_iter = True
							continue
							
					if er.result is not None:
						if self.ext_result_q is not None:
							await self.ext_result_q.put(EnumResultFinal(er.result, 'session', None, er.target, er.target_id))
						out_buffer.append(EnumResultFinal(er.result, 'session', None, er.target, er.target_id))
						self.__total_sessions += 1
							
						if self.show_pbar is True:
							pbar['sessions'].update(1)
					
					if er.status == EnumResultStatus.ERROR:
						self.__total_errors += 1
						if self.show_pbar is True:
							pbar['connerrors'].update(1)


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
		finally:
			if self.ext_result_q is not None:
				await self.ext_result_q.put(EnumResultFinal(None, 'finished', None, None, None))

	async def terminate(self):
		for worker in self.workers:
			worker.cancel()
		if self.result_processing_task is not None:
			self.result_processing_task.cancel()		

	async def setup(self):
		try:
			if self.res_q is None:
				self.res_q = asyncio.Queue(self.worker_count)
				self.result_processing_task = asyncio.create_task(self.result_processing())
			if self.task_q is None:
				self.task_q = asyncio.Queue(self.worker_count)

			for _ in range(self.worker_count):
				self.workers.append(asyncio.create_task(self.worker()))

			return True, None
		except Exception as e:
			return None, e

	async def __generate_targets(self):
		if self.enum_url is True:
			self.__total_targets += 1
			await self.task_q.put((str(uuid.uuid4()), self.smb_mgr.get_target().get_hostname_or_ip()))
			
		for target_gen in self.target_gens:
			async for uid, target, err in target_gen.generate():
				if err is not None:
					print('Target gen error! %s' % err)
					break
				
				self.__total_targets += 1
				await self.task_q.put((uid, target))
				await asyncio.sleep(0)

		self.__gens_finished = True
	
	async def run(self):
		try:
			_, err = await self.setup()
			if err is not None:
				raise err
			
			gen_task = asyncio.create_task(self.__generate_targets())
			
			await asyncio.gather(*self.workers)
			await self.result_processing_task
			return True, None
		except Exception as e:
			logger.exception('run')
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
	parser.add_argument('-w', '--smb-worker-count', type=int, default=100, help='Parallell count')
	parser.add_argument('-o', '--out-file', help='Output file path.')
	parser.add_argument('-s', '--stdin', action='store_true', help='Read targets from stdin')
	parser.add_argument('--url', help='Connection URL base, target can be set to anything. Owerrides all parameter based connection settings! Example: "smb2+ntlm-password://TEST\\victim@test"')
	parser.add_argument('--progress', action='store_true', help='Show progress bar')
	parser.add_argument('--json', action='store_true', help='Output in JSON format')
	parser.add_argument('--tsv', action='store_true', help='Output in TSV format. (TAB Separated Values)')
	parser.add_argument('targets', nargs='*', help = 'Hostname or IP address or file with a list of targets')

	args = parser.parse_args()

	if args.verbose >=1:
		logger.setLevel(logging.DEBUG)

	if args.verbose > 2:
		print('setting deepdebug')
		logger.setLevel(1) #enabling deep debug
		asyncio.get_event_loop().set_debug(True)
		logging.basicConfig(level=logging.DEBUG)

	output_type = 'str'
	if args.json is True:
		output_type = 'json'
	if args.tsv is True:
		output_type = 'tsv'

	smb_url = None
	if args.url is not None:
		smb_url = args.url
	else:
		try:
			smb_url = SMBConnectionParams.parse_args(args)
		except Exception as e:
			print('Either URL or all connection parameters must be set! Error: %s' % str(e))
			sys.exit(1)
	

	enumerator = SMBSessionEnum(
		smb_url,
		worker_count = args.smb_worker_count,
		out_file = args.out_file,
		show_pbar = args.progress,
		output_type = output_type,
	)
	
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
		enumerator.enum_url = True

	await enumerator.run()

def main():
	asyncio.run(amain())

if __name__ == '__main__':
	main()