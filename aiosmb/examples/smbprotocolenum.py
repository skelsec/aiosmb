
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
from aiosmb.protocol.common import SMB_NEGOTIATE_PROTOCOL_TEST, NegotiateDialects

from tqdm import tqdm

class SMBProtocolEnumProgressResult:
	def __init__(self, total_targets, total_finished, gens_finished, target):
		self.total_targets = total_targets
		self.total_finished = total_finished
		self.gens_finished = gens_finished
		self.target = target

class SMBProtocolEnumResultInner:
	def __init__(self, target_id, target, result, error = None, status = EnumResultStatus.RESULT):
		self.target_id = target_id
		self.target = target
		self.error = error
		self.result = result
		self.status = status

class SMBProtocolEnumData:
	def __init__(self, target_id, target, protocol, sign_en, sign_req, reply):
		self.target_id = target_id
		self.target = target
		self.protocol = protocol
		self.sign_en = sign_en
		self.sign_req = sign_req
		self.reply = reply

SMBPROTOCOLENUM_TSV_HDR = ['target', 'target_id', 'protocol', 'sigen', 'sigreq' ]


class SMBProtocolEnumResult:
	def __init__(self, obj, otype):
		self.obj = obj
		self.otype = otype

	def __str__(self):
		if self.otype == 'result':
			return '[R] %s | %s | %s | %s | %s' % (self.obj.target, self.obj.target_id, self.obj.protocol, self.obj.sign_en, self.obj.sign_req)
	
		elif self.otype == 'error':
			return '[E] %s | %s | %s' % (self.obj.target, self.obj.target_id, self.obj.error)

		elif self.otype == 'progress':
			return '[P] %s/%s | %s | %s' % (self.obj.total_targets, self.obj.total_finished, str(self.obj.gens_finished), self.obj.target)

		else:
			return '[UNK]'
	
	def to_dict(self):
		if self.otype == 'result':
			t = {}
			t['target'] = self.obj.target
			t['target_id'] = self.obj.target_id
			t['protocol'] = self.obj.protocol
			t['sigen'] = self.obj.sign_en
			t['sigreq'] = self.obj.sign_req
			return t
		return {}
	
	def to_json(self):
		dd = self.to_dict()
		return json.dumps(dd, cls = UniversalEncoder)

	def to_tsv(self, hdrs = SMBPROTOCOLENUM_TSV_HDR, separator = '\t'):
		if self.otype == 'result':
			dd = self.to_dict()
			data = [ str(dd[x]) for x in hdrs ]
			return separator.join(data)

		return ''

class SMBProtocolEnum:
	def __init__(self, worker_count = 100, timeout = 5, only_signing = False, protocols = SMB_NEGOTIATE_PROTOCOL_TEST, exclude_target = [], show_pbar = False, ext_result_q = None, output_type = 'str', out_file = None):
		self.target_gens = []
		self.timeout = timeout
		self.worker_count = worker_count
		self.task_q = None
		self.res_q = None
		self.exclude_target = exclude_target
		self.workers = []
		self.result_processing_task = None
		self.show_pbar = show_pbar
		self.ext_result_q = ext_result_q
		self.output_type = output_type
		self.out_file = out_file
		self.__gens_finished = False
		self.__total_targets = 0
		self.__total_finished = 0
		self.protocols = protocols
		self.only_signing = only_signing

	async def __executor(self, tid, target):
		try:
			for protocol in self.protocols:
				smb_mgr = SMBConnectionURL('smb2+ntlm-password://%s/?timeout=%s' % (target, self.timeout))
				connection = smb_mgr.create_connection_newtarget(target)
				res, sign_en, sign_req, rply, err = await connection.protocol_test([protocol])
				if err is not None:
					raise err
				
				er = SMBProtocolEnumResultInner(tid, target, (protocol, res, sign_en, sign_req, rply, err))
				await self.res_q.put(er)
				if self.only_signing is True:
					return
		except asyncio.CancelledError:
			return
		except Exception as e:
			await self.res_q.put(SMBProtocolEnumResultInner(tid, target, None, error = e, status = EnumResultStatus.ERROR))
		finally:
			await self.res_q.put(SMBProtocolEnumResultInner(tid, target, None, status = EnumResultStatus.FINISHED))

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
					pass
		except asyncio.CancelledError:
			return
				
		except Exception as e:
			return e

	async def result_processing(self):
		try:
			pbar = None
			if self.show_pbar is True:
				pbar = {}
				pbar['targets']         = tqdm(desc='Targets                ', unit='', position=0)
				pbar['smb1']            = tqdm(desc='SMBv1                  ', unit='', position=1)
				pbar['signenabled']     = tqdm(desc='Singing enabled        ', unit='', position=2)
				pbar['signnotenforced'] = tqdm(desc='Singning NOT enforced  ', unit='', position=3)
				pbar['connerrors']      = tqdm(desc='Conn Errors            ', unit='', position=4)
			
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
								t = res.to_tsv()
								if t == '':
									continue
								out_data += '%s\r\n' % res.to_tsv()
						elif self.output_type == 'json':
							for res in out_buffer:
								t = res.to_json()
								if len(t) == 2:
									continue
								out_data += '%s\r\n' % t
					
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
						
						obj = SMBProtocolEnumProgressResult(self.__total_targets, self.__total_finished, self.__gens_finished, er.target)
						if self.ext_result_q is not None:
							await self.ext_result_q.put(SMBProtocolEnumResult(obj, 'progress'))
						out_buffer.append(SMBProtocolEnumResult(obj, 'progress'))
						if self.__total_finished == self.__total_targets and self.__gens_finished is True:
							final_iter = True
							continue

					elif er.status == EnumResultStatus.RESULT:
						protocol, result, sign_en, sign_req, rply, err = er.result
						if protocol == NegotiateDialects.WILDCARD:
							protocol = 'SMB1' #replacing this bc of logic in connection
						else:
							protocol = protocol.name.upper()
						if result is True:
							if sign_en is True:
								sign_en = 'E'
							else:
								sign_en = 'D'
							if sign_req is True:
								sign_req = 'REQ'
							else:
								sign_req = 'NOTREQ'
						else:
							sign_en = None
							sign_req = None
						
						if self.show_pbar is True:
							if protocol == 'SMB1':
								pbar['smb1'].update(1)
							if sign_en == 'E':
								pbar['signenabled'].update(1)
							if sign_req == 'NOTREQ':
								pbar['signnotenforced'].update(1)

						data = SMBProtocolEnumData(er.target_id, er.target, protocol, sign_en, sign_req, rply)

						if self.ext_result_q is not None:
							await self.ext_result_q.put(SMBProtocolEnumResult(data, 'result'))
						out_buffer.append(SMBProtocolEnumResult(data, 'result'))
					
					elif er.status == EnumResultStatus.ERROR:
						if self.ext_result_q is not None:
							await self.ext_result_q.put(SMBProtocolEnumResult(er, 'error'))
						if self.show_pbar is True:
							pbar['connerrors'].update(1)
						out_buffer.append(SMBProtocolEnumResult(er, 'error'))					
					
				except asyncio.CancelledError:
					return
				except Exception as e:
					print(e)

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
		try:		
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
		except Exception as e:
			logger.exception('targetgen')
	
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

	parser = argparse.ArgumentParser(description='SMB Protocol enumerator. Tells which dialects suported by the remote end')
	parser.add_argument('-v', '--verbose', action='count', default=0)
	parser.add_argument('-w', '--smb-worker-count', type=int, default=100, help='Parallell count')
	parser.add_argument('-t', '--timeout', type=int, default=50, help='Timeout for each connection')
	parser.add_argument('--signing', action='store_true', help='Only check for the singing properties. (faster)')
	parser.add_argument('-s', '--stdin', action='store_true', help='Read targets from stdin')
	parser.add_argument('--json', action='store_true', help='Output in JSON format')
	parser.add_argument('--tsv', action='store_true', help='Output in TSV format. (TAB Separated Values)')
	parser.add_argument('--progress', action='store_true', help='Show progress bar')
	parser.add_argument('-o', '--out-file', help='Output file path.')
	parser.add_argument('targets', nargs='*', help = 'Hostname or IP address or file with a list of targets')
	args = parser.parse_args()
	
	if args.verbose >=1:
		logger.setLevel(logging.INFO)

	if args.verbose > 2:
		logger.setLevel(1) #enabling deep debug
		asyncio.get_event_loop().set_debug(True)
		logging.basicConfig(level=logging.DEBUG)
	
	output_type = 'str'
	if args.json is True:
		output_type = 'json'
	if args.tsv is True:
		output_type = 'tsv'

	enumerator = SMBProtocolEnum(worker_count = args.smb_worker_count, timeout = args.timeout, only_signing = args.signing, show_pbar=args.progress, out_file=args.out_file, output_type=output_type)

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
	if args.progress is False:
		print('[+] Done!')

def main():
	asyncio.run(amain())

if __name__ == '__main__':
	main()