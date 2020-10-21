
import asyncio
import traceback
import logging

from aiosmb import logger
from aiosmb._version import __banner__
from aiosmb.commons.connection.url import SMBConnectionURL
from aiosmb.connection import SMBConnection
from aiosmb.dcerpc.v5.interfaces.even6 import SMBEven6

"""
Query example:
"*[System/EventID=5312]"
"""

async def amain(url, src = "Security", query = '*', max_entries = 100):
	su = SMBConnectionURL(url)
	conn = su.get_connection()

	_, err = await conn.login()
	if err is not None:
		print('Failed to connect to server! %s' % err)
		return False, err
	else:
		logger.debug('SMB Connected!')
	ei = SMBEven6(conn)
	_, err = await ei.connect()
	if err is not None:
		print('Error during DCE connection! %s' % err)
		return False, err
	logger.debug('DCE Connected!')
	
	
	sec_handle, err = await ei.register_query(src, query=query)
	if err is not None:
		print(err)
		return False, err

	async for res, err in ei.query_next(sec_handle, max_entries, as_xml=True):
		if err is not None:
			print(err)
			break
		
		try:
			print(res)
		except Exception as e:
			print(e)
			pass

	await ei.close()
	await conn.disconnect()

	return True, None


def main():
	import argparse

	parser = argparse.ArgumentParser(description='Event query example')
	parser.add_argument('-v', '--verbose', action='count', default=0)
	parser.add_argument('--src', default="Security", help = 'log source to query')
	parser.add_argument('-q', '--query', default="*", help = 'query string')
	parser.add_argument('-m', '--max_entries', type=int, default=100, help = 'max element count to retrieve')
	
	parser.add_argument('smb_url', help = 'Connection string that describes the authentication and target. Example: smb+ntlm-password://TEST\\Administrator:password@10.10.10.2')
	
	args = parser.parse_args()
	print(__banner__)

	if args.verbose >=1:
		logger.setLevel(logging.DEBUG)

	asyncio.run(amain(args.smb_url, src = args.src, query = args.query, max_entries = args.max_entries))


	

if __name__ == '__main__':
	main()