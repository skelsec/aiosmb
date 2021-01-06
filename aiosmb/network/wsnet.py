
#
#
#
#
#
#


import enum
import asyncio
import ipaddress

from aiosmb import logger
from aiosmb.commons.exceptions import *

from pyodidewsnet.client import WSNetworkTCP


class WSNetProxyConnection:
	"""
	Generic asynchronous TCP socket class, nothing SMB related.
	Creates the connection and channels incoming/outgoing bytes via asynchonous queues.
	"""
	def __init__(self, target = None, socket = None):
		self.target = target
		self.socket = socket #for future, if we want a custom soscket
		
		self.client = None

		self.out_queue = None#asyncio.Queue()
		self.in_queue = None#asyncio.Queue()
		
	async def disconnect(self):
		"""
		Disconnects from the socket.
		Stops the reader and writer streams.
		"""
		if self.client is not None:
			try:
				await self.client.terminate()
			except:
				pass
		
	async def connect(self):
		try:	
			self.out_queue = asyncio.Queue()
			self.in_queue = asyncio.Queue()

			self.client = WSNetworkTCP(self.target.ip, int(self.target.port), self.in_queue, self.out_queue)
			_, err = await self.client.run()
			if err is not None:
				raise err
			return True, None
		except Exception as e:
			return False, e

			

			


			