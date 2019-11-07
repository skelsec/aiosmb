import asyncio

from aiosmb import logger
from aiosmb.commons.exceptions import *
from aiosmb.commons.connection.proxy import SMBProxyType
from aiosmb.network.socks5 import Socks5ProxyConnection
from aiosmb.network.multiplexornetwork import MultiplexorProxyConnection
from aiosmb.commons.utils.decorators import red, rr

class DCERPCTCPConnection:
	def __init__(self, ip, port):
		self.ip = ip
		self.port = port
		self.timeout = 2
		
		self.in_queue = asyncio.Queue()
		self.out_queue = asyncio.Queue()
		
		
		self.disconnected = asyncio.Event()
		self.shutdown_evt = asyncio.Event()

		self.__incoming_task = None
		self.__outgoing_task = None
		
	
	async def handle_incoming(self):
		"""
		Reads data bytes from the socket and dispatches it to the incoming queue
		"""
		try:
			while not self.disconnected.is_set() or not self.shutdown_evt.is_set():
				data = await self.reader.read(4096)
				await self.in_queue.put((data, None))
		
		except asyncio.CancelledError:
			#the SMB connection is terminating
			return
			
		except Exception as e:	
			logger.exception('[DCERPCTCPConnection] handle_incoming %s' % str(e))
			await self.in_queue.put((None, e))
			await self.disconnect()
			
		
	async def handle_outgoing(self):
		"""
		Reads data bytes from the outgoing queue and dispatches it to the socket
		"""
		try:
			while not self.disconnected.is_set() or not self.shutdown_evt.is_set():
				data = await self.out_queue.get()
				self.writer.write(data)
				await self.writer.drain()
		except asyncio.CancelledError:
			#the SMB connection is terminating
			return
			
		except Exception as e:
			logger.exception('[DCERPCTCPConnection] handle_outgoing %s' % str(e))
			await self.disconnect()
	
	@red
	async def connect(self):
		con = asyncio.open_connection(self.ip, self.port)
		
		try:
			self.reader, self.writer = await asyncio.wait_for(con, int(self.timeout))
		except asyncio.TimeoutError:
			logger.debug('[DCERPCTCPConnection] Connection timeout')
			raise SMBConnectionTimeoutException() 
		except ConnectionRefusedError:
			logger.debug('[DCERPCTCPConnection] Connection refused')
			raise SMBConnectionRefusedException()
		except asyncio.CancelledError:
			#the SMB connection is terminating
			return
		except Exception as e:
			logger.exception('[DCERPCTCPConnection] connect generic exception')
			raise e
		

		self.__incoming_task = asyncio.create_task(self.handle_incoming())
		self.__outgoing_task = asyncio.create_task(self.handle_outgoing())
		
		
		return True, None
	
	@red
	async def disconnect(self):
		"""
		Disconnects from the socket.
		Stops the reader and writer streams.
		"""
		if self.__incoming_task:
			self.__incoming_task.cancel()
		if self.__outgoing_task:
			self.__outgoing_task.cancel()

		self.reader = None
		try:
			self.writer.close()
		except:
			pass
		self.writer = None
		self.disconnected.set()

		return True, None


class DCERPCTCPTransport:
	def __init__(self, target):
		self.target = target
		
		self.buffer = b''
		self.data_in_evt = asyncio.Event()
		self.exception_evt = asyncio.Event()
		self.connection = None

		self.__last_exception = None
		self.__incoming_task = None
		self.__outgoing_task = None

		self._max_send_frag = 1024

	@red
	async def get_connection_layer(self):
		if self.target.proxy is None:
			return DCERPCTCPConnection(self.target.ip, self.target.port), None
			
		elif self.target.proxy.type in [SMBProxyType.SOCKS5, SMBProxyType.SOCKS5_SSL]:
			return Socks5ProxyConnection(target = self.target), None

		elif self.target.proxy.type in [SMBProxyType.MULTIPLEXOR, SMBProxyType.MULTIPLEXOR_SSL]:
			mpc = MultiplexorProxyConnection(self.target)
			socks_proxy = await mpc.connect()
			return socks_proxy, None

		else:
			raise Exception('Unknown proxy type %s' % self.target.proxy.type)


	async def __handle_incoming(self):
		try:
			while True:
				data, res = await self.connection.in_queue.get()
				if data is None:
					self.__last_exception = res
					self.exception_evt.set()
					return
				self.buffer += data
				self.data_in_evt.set()
		except asyncio.CancelledError:
			return
		except Exception as e:
			logger.exception('__handle_incoming')
			return
	
	@red
	async def connect(self):
		self.connection, _ = await rr(self.get_connection_layer())
		await self.connection.connect()

		self.__incoming_task = asyncio.create_task(self.__handle_incoming())
		
		return True, None
	
	@red
	async def disconnect(self):
		try:
			if self.__incoming_task:
				self.__incoming_task.cancel()
			if self.data_in_evt:
				self.data_in_evt.set()
			await self.connection.disconnect()
		except:
			pass

		return True, None
	
	@red
	async def send(self, data, forceWriteAndx = 0, forceRecv = 0):
		if self.__last_exception is not None:
			return None, self.__last_exception
		
		if self._max_send_frag:
			offset = 0
			while 1:
				toSend = data[offset:offset+self._max_send_frag]
				if not toSend:
					break
				await self.connection.out_queue.put(data)
				offset += len(toSend)
				
		else:
			await self.connection.out_queue.put(data)
		
		return True, None
	
	@red
	async def recv(self, count, forceRecv = 0):
		try:
			while len(self.buffer) < count:
				#waiting until buffer has enough data
				self.data_in_evt.clear()
				await asyncio.wait_for(self.data_in_evt.wait(), timeout = self.target.timeout)
			
			if self.__last_exception is not None:
				return None, self.__last_exception

			data = self.buffer[:count]
			self.buffer = self.buffer[count:]
			return data, None
		except Exception as e:
			return None, e
		