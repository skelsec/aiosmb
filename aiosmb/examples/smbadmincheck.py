
import asyncio
import enum
import uuid
import logging
import json

from aiosmb import logger
from aiosmb.examples.scancommons.targetgens import *
from aiosmb.examples.scancommons.internal import *
from aiosmb.examples.scancommons.utils import *
from aiosmb.commons.utils.univeraljson import UniversalEncoder

from aiosmb.commons.connection.url import SMBConnectionURL
from aiosmb.commons.interfaces.machine import SMBMachine
from aiosmb.commons.interfaces.share import SMBShare
from aiosmb.dcerpc.v5.interfaces.remoteregistry import RRP
from aiosmb.dcerpc.v5.interfaces.servicemanager import SMBRemoteServieManager

from tqdm import tqdm

import traceback


class SMBAdminEnumResultInner:
	def __init__(self, target_id, target, error = None, status = EnumResultStatus.RESULT):
		self.target_id = target_id
		self.target = target
		self.error = error
		self.share = None
		self.registry = None
		self.servicemgr = None
		self.status = status
	
	

class SMBAdminEnumProgressResult:
	def __init__(self, total_targets, total_finished, gens_finished, target):
		self.total_targets = total_targets
		self.total_finished = total_finished
		self.gens_finished = gens_finished
		self.target = target

SMBADMINENUM_TSV_HDR = ['target', 'target_id', 'share', 'servicemgr', 'registry' ]


class SMBAdminEnumResult:
	def __init__(self, obj, otype):
		self.obj = obj
		self.otype = otype

	def to_dict(self):
		if self.otype == 'result':
			t = {}
			t['target'] = self.obj.target
			t['target_id'] = self.obj.target_id
			t['share'] = self.obj.share
			t['servicemgr'] = self.obj.servicemgr
			t['registry'] = self.obj.registry
			return t
		return {}
	
	def to_json(self):
		dd = self.to_dict()
		return json.dumps(dd, cls = UniversalEncoder)

	def to_tsv(self, hdrs = SMBADMINENUM_TSV_HDR, separator = '\t'):
		if self.otype == 'result':
			dd = self.to_dict()
			data = [ str(dd[x]) for x in hdrs ]
			return separator.join(data)

		return ''
	
	def __str__(self):
		if self.otype == 'result':
			t = ''
			if self.obj.share is True:
				t += '[R] %s | %s | SHARE\r\n' % (self.obj.target, self.obj.target_id)
			if self.obj.registry is True:
				t += '[R] %s | %s | REG\r\n' % (self.obj.target, self.obj.target_id)
			if self.obj.servicemgr is True:
				t += '[R] %s | %s | SRV\r\n' % (self.obj.target, self.obj.target_id)
			return t
	
		elif self.otype == 'error':
			return '[E] %s | %s | %s' % (self.obj.target, self.obj.target_id, self.obj.error)

		elif self.otype == 'progress':
			return '[P] %s/%s | %s | %s' % (self.obj.total_targets, self.obj.total_finished, str(self.obj.gens_finished), self.obj.target)

		else:
			return '[UNK]'
	


class SMBAdminCheck:
	def __init__(self, smb_url, worker_count = 100, enum_url = True, exclude_target = [], show_pbar = False, ext_result_q=None, output_type = 'str', out_file = None):
		self.target_gens = []
		self.smb_mgr = SMBConnectionURL(smb_url)
		self.worker_count = worker_count
		self.task_q = None
		self.res_q = None
		self.workers = []
		self.result_processing_task = None
		self.enum_url = enum_url
		self.exclude_target = []
		self.show_pbar = show_pbar
		self.ext_result_q = ext_result_q
		self.output_type = output_type
		self.out_file = out_file
		self.__gens_finished = False
		self.__total_targets = 0
		self.__total_finished = 0

	async def __executor(self, tid, target):
		try:
			connection = self.smb_mgr.create_connection_newtarget(target)
			async with connection:
				_, err = await connection.login()
				if err is not None:
					raise err
				
				res = SMBAdminEnumResultInner(tid, target)
				share = SMBShare(
					name = 'ADMIN$',
					fullpath = '\\\\%s\\%s' % (connection.target.get_hostname_or_ip(), 'ADMIN$')
				)
				_, err = await share.connect(connection)
				res.share = True if err is None else False

				rrp = RRP(connection)
				_, err = await rrp.connect()
				res.registry = True if err is None else False


				srvmgr = SMBRemoteServieManager(connection)
				_, err = await srvmgr.connect()
				res.servicemgr = True if err is None else False

				await self.res_q.put(res)


		except asyncio.CancelledError:
			return
		except Exception as e:
			await self.res_q.put(SMBAdminEnumResultInner(tid, target, error = e, status = EnumResultStatus.ERROR))
		finally:
			await self.res_q.put(SMBAdminEnumResultInner(tid, target, status = EnumResultStatus.FINISHED))

	async def worker(self):
		try:
			while True:
				indata = await self.task_q.get()
				if indata is None:
					return
				
				tid, target = indata
				try:
					await asyncio.wait_for(self.__executor(tid, target), timeout=10)
				except asyncio.CancelledError:
					return
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
				pbar['targets']    = tqdm(desc='Targets        ', unit='', position=0)
				pbar['share']      = tqdm(desc='C$ Access      ', unit='', position=1)
				pbar['reg']        = tqdm(desc='Registry Access', unit='', position=2)
				pbar['svc']        = tqdm(desc='Service  Access', unit='', position=3)
				pbar['connerrors'] = tqdm(desc='Conn Errors    ', unit='', position=4)

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
					
					if len(out_buffer) >= 1000 or final_iter and self.ext_result_q is None:
						out_data = ''
						if self.output_type == 'str':
							out_data = '\r\n'.join([str(x) for x in out_buffer])
						elif self.output_type == 'tsv':
							for res in out_buffer:
								out_data += '%s\r\n' % res.to_tsv()
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
						
						obj = SMBAdminEnumProgressResult(self.__total_targets, self.__total_finished, self.__gens_finished, er.target)
						if self.ext_result_q is not None:
							await self.ext_result_q.put(SMBAdminEnumResult(obj, 'progress'))
						out_buffer.append(SMBAdminEnumResult(obj, 'progress'))
						if self.__total_finished == self.__total_targets and self.__gens_finished is True:
							final_iter = True
							continue
					
					elif er.status == EnumResultStatus.RESULT:
						if self.show_pbar is True:
							if er.share is True:
								pbar['share'].update(1)
							if er.registry is True:
								pbar['reg'].update(1)
							if er.servicemgr is True:
								pbar['svc'].update(1)

						if self.ext_result_q is not None:
							await self.ext_result_q.put(SMBAdminEnumResult(er, 'result'))
						out_buffer.append(SMBAdminEnumResult(er, 'result'))
					
					elif er.status == EnumResultStatus.ERROR:
						if self.ext_result_q is not None:
							await self.ext_result_q.put(SMBAdminEnumResult(er, 'error'))
						if self.show_pbar is True:
							pbar['connerrors'].update(1)
						out_buffer.append(SMBAdminEnumResult(er, 'error'))

				except asyncio.CancelledError:
					return
				except Exception as e:
					logger.exception('result_processing inner')
					continue
		except asyncio.CancelledError:
			return
		except Exception as e:
			logger.exception('result_processing main')

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
				self.task_q = asyncio.Queue()

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
				
				if target in self.exclude_target:
					continue
				
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
			print(e)
			return None, e

async def amain():
	import argparse
	import sys
	from aiosmb.commons.connection.params import SMBConnectionParams

	epilog = """
Output legend:
    [SHARE] C$ is accessible
    [SRV] Remote Service Manager is accessible
    [REG] Remote registry is accessible
    [E] Error
    [P] Progress (current/total)
"""

	parser = argparse.ArgumentParser(description='SMB Share enumerator', formatter_class=argparse.RawDescriptionHelpFormatter, epilog=epilog)
	SMBConnectionParams.extend_parser(parser)
	parser.add_argument('-v', '--verbose', action='count', default=0)
	parser.add_argument('-w', '--smb-worker-count', type=int, default=100, help='Parallell count')
	parser.add_argument('-o', '--out-file', help='Output file path.')
	parser.add_argument('-s', '--stdin', action='store_true', help='Read targets from stdin')
	parser.add_argument('--url', help='Connection URL base, target can be set to anything. Owerrides all parameter based connection settings! Example: "smb2+ntlm-password://TEST\\victim@test"')
	parser.add_argument('--json', action='store_true', help='Output in JSON format')
	parser.add_argument('--tsv', action='store_true', help='Output in TSV format. (TAB Separated Values)')
	parser.add_argument('--progress', action='store_true', help='Show progress bar')
	parser.add_argument('targets', nargs='*', help = 'Hostname or IP address or file with a list of targets')
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

	output_type = 'str'
	if args.json is True:
		output_type = 'json'
	if args.tsv is True:
		output_type = 'tsv'
	
	enumerator = SMBAdminCheck(smb_url, worker_count = args.smb_worker_count, output_type=output_type, out_file=args.out_file, show_pbar = args.progress)
	
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