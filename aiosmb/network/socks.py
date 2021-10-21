
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

from asysocks.client import SOCKSClient
from asysocks.common.comms import SocksQueueComms


class SocksProxyConnection:
	"""
	Generic asynchronous TCP socket class, nothing SMB related.
	Creates the connection and channels incoming/outgoing bytes via asynchonous queues.
	"""
	def __init__(self, target = None, socket = None):
		self.target = target
		self.socket = socket #for future, if we want a custom soscket
		
		self.client = None
		self.proxy_task = None

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

		if self.proxy_task is not None:
			self.proxy_task.cancel()
		
	async def connect(self):
		try:	
			self.out_queue = asyncio.Queue()
			self.in_queue = asyncio.Queue()
			comms = SocksQueueComms(self.out_queue, self.in_queue)

			self.target.proxy.target[-1].endpoint_ip = self.target.ip
			self.target.proxy.target[-1].endpoint_port = int(self.target.port)
			self.target.proxy.target[-1].endpoint_timeout = int(self.target.timeout)
			self.target.proxy.target[-1].timeout = int(self.target.timeout)

			self.client = SOCKSClient(comms, self.target.proxy.target)
			self.proxy_task = asyncio.create_task(self.client.run())
			return True, None
		except Exception as e:
			return False, e

			

			


			