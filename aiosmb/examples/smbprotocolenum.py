
import asyncio
import enum
import uuid
import logging

from aiosmb import logger
from aiosmb.commons.connection.url import SMBConnectionURL
from aiosmb.commons.interfaces.machine import SMBMachine
from aiosmb.protocol.common import SMB_NEGOTIATE_PROTOCOL_TEST, NegotiateDialects

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


class SMBProtocolEnum:
	def __init__(self, worker_count = 100, timeout = 5, only_signing = False, protocols = SMB_NEGOTIATE_PROTOCOL_TEST):
		self.target_gens = []
		self.timeout = timeout
		self.worker_count = worker_count
		self.task_q = None
		self.res_q = None
		self.workers = []
		self.result_processing_task = None
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
				er = EnumResult(tid, target, (protocol, res, sign_en, sign_req, rply, err))
				await self.res_q.put(er)
				if self.only_signing is True:
					return
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
			while True:
				try:
					er = await self.res_q.get()

					if er.result is not None:
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
							sign_en = '?'
							sign_req = '?'
						print('[%s][%s][%s/%s] %s' % (er.target, protocol, sign_en, sign_req, result))
					
					if er.status == EnumResultStatus.ERROR:
						print('[%s][E][%s]' % (er.target, er.error))
					
					if er.status == EnumResultStatus.FINISHED:
						self.__total_finished += 1
						print('[P][%s/%s][%s]' % (self.__total_targets, self.__total_finished, str(self.__gens_finished)))
						if self.__total_finished == self.__total_targets and self.__gens_finished is True:
							
							asyncio.create_task(self.terminate())
							return
				except asyncio.CancelledError:
					return
				except Exception as e:
					print(e)

		except asyncio.CancelledError:
			return
		except Exception as e:
			print(e)

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
	
	async def run(self):
		try:
			_, err = await self.setup()
			if err is not None:
				raise err
			
			for target_gen in self.target_gens:
				total, err = await target_gen.run(self.task_q)
				self.__total_targets += total
				if err is not None:
					print('Target gen error! %s' % err)

			self.__gens_finished = True
			
			await asyncio.gather(*self.workers)
			return True, None
		except Exception as e:
			print(e)
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
	parser.add_argument('targets', nargs='*', help = 'Hostname or IP address or file with a list of targets')
	args = parser.parse_args()

	if args.verbose >=1:
		logger.setLevel(logging.DEBUG)

	if args.verbose > 2:
		print('setting deepdebug')
		logger.setLevel(1) #enabling deep debug
		asyncio.get_event_loop().set_debug(True)
		logging.basicConfig(level=logging.DEBUG)

	enumerator = SMBProtocolEnum(worker_count = args.smb_worker_count, timeout = args.timeout, only_signing = args.signing)

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
	print('[+] Done!')

def main():
	asyncio.run(amain())

if __name__ == '__main__':
	main()