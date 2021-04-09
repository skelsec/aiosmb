import asyncio

from aiosmb import logger
from aiosmb.commons.exceptions import *
from aiosmb.commons.connection.proxy import SMBProxyType
from aiosmb.network.socks import SocksProxyConnection
from aiosmb.network.multiplexornetwork import MultiplexorProxyConnection
from aiosmb.dcerpc.v5.rpcrt import MSRPCRespHeader

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
				try:
					msg_data = b''
					data = await self.reader.readexactly(24)
					msg_data += data
					response_header = MSRPCRespHeader(msg_data)
					
					data = await self.reader.readexactly(response_header['frag_len'] - 24)
					msg_data += data
					await self.in_queue.put((msg_data, None))
					await asyncio.sleep(0)
				
				except asyncio.CancelledError:
					return
				except Exception as e:
					await self.in_queue.put((None, e))
					return
		
		except asyncio.CancelledError:
			#the connection is terminating
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
			#the connection is terminating
			return
			
		except Exception as e:
			logger.exception('[DCERPCTCPConnection] handle_outgoing %s' % str(e))
			await self.disconnect()
	
	async def connect(self):
		try:
			con = asyncio.open_connection(self.ip, self.port)
			self.reader, self.writer = await asyncio.wait_for(con, None)
		except asyncio.TimeoutError:
			logger.debug('[DCERPCTCPConnection] Connection timeout')
			return None, SMBConnectionTimeoutException() 
		except ConnectionRefusedError:
			logger.debug('[DCERPCTCPConnection] Connection refused')
			return None, SMBConnectionRefusedException()
		except Exception as e:
			logger.exception('[DCERPCTCPConnection] connect generic exception')
			return None, e
		

		self.__incoming_task = asyncio.create_task(self.handle_incoming())
		self.__outgoing_task = asyncio.create_task(self.handle_outgoing())
		
		return True, None
	
	async def disconnect(self):
		"""
		Disconnects from the socket.
		Stops the reader and writer streams.
		"""
		try:
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
		except Exception as e:
			return False, e


class DCERPCTCPTransport:
	def __init__(self, target):
		self.target = target
		
		self.buffer = b''
		self.data_in_evt = asyncio.Event()
		self.exception_evt = asyncio.Event()
		self.connection = None
		self.is_proxy = False
		self.msg_in_queue = asyncio.Queue()

		self.__last_exception = None
		self.__incoming_task = None
		self.__outgoing_task = None

		self._max_send_frag = 1024

	
	async def get_connection_layer(self):
		try:
			if self.target.proxy is None:
				return DCERPCTCPConnection(self.target.ip, self.target.port), None
				
			elif self.target.proxy.type in [SMBProxyType.WSNET,SMBProxyType.WSNETWS, SMBProxyType.WSNETWSS, SMBProxyType.SOCKS5, SMBProxyType.SOCKS5_SSL, SMBProxyType.SOCKS4, SMBProxyType.SOCKS4_SSL]:
				self.is_proxy = True
				return SocksProxyConnection(target = self.target), None

			elif self.target.proxy.type in [SMBProxyType.MULTIPLEXOR, SMBProxyType.MULTIPLEXOR_SSL]:
				self.is_proxy = True
				mpc = MultiplexorProxyConnection(self.target)
				socks_proxy, err = await mpc.connect()
				return socks_proxy, err

			else:
				raise Exception('Unknown proxy type %s' % self.target.proxy.type)
		except Exception as e:
			return None, e


	async def __handle_incoming(self):
		try:
			data = b''
			while True:
				x, err = await self.connection.in_queue.get()
				if err is not None:
					raise err
				data += x
				if len(data) >= 24: #MSRPCRespHeader._SIZE
					response_header = MSRPCRespHeader(data)
					while len(data) < response_header['frag_len']:
						x, err = await self.connection.in_queue.get()
						if err is not None:
							raise err
						data += x

					response_data = data[:response_header['frag_len']]
					data = data[response_header['frag_len']:]
				
					await self.msg_in_queue.put(response_data)

		except asyncio.CancelledError:
			self.exception_evt.set()
			return
		except Exception as e:
			logger.exception('__handle_incoming')
			self.exception_evt.set()
			return
	
	async def connect(self):
		try:
			self.connection, err = await self.get_connection_layer()
			if err is not None:
				raise err
			await self.connection.connect()

			#self.__incoming_task = asyncio.create_task(self.__handle_incoming())
			
			return True, None
		except Exception as e:
			return None, e
	

	async def disconnect(self):
		try:
			if self.__incoming_task:
				self.__incoming_task.cancel()
			if self.data_in_evt:
				self.data_in_evt.set()
			await self.connection.disconnect()


			return True, None
		except Exception as e:
			return False, e
	
	
	async def send(self, data, forceWriteAndx = 0, forceRecv = 0):
		try:
			if self.__last_exception is not None:
				return None, self.__last_exception
			
			if self._max_send_frag:
				offset = 0
				while True:
					toSend = data[offset:offset+self._max_send_frag]
					if not toSend:
						break
					await self.connection.out_queue.put(toSend)
					offset += len(toSend)
					
			else:
				await self.connection.out_queue.put(data)
			
			return True, None
		except Exception as e:
			return None, e
	
	
	async def recv(self, count, forceRecv = 0):
		try:
			if self.is_proxy is False:
				# the TCP call already buffers one messages per get
				data, err = await asyncio.wait_for(self.connection.in_queue.get(), timeout = None)
				return data, err
			
			err = None
			while True:
				if len(self.buffer) >= 24:
					response_header = MSRPCRespHeader(self.buffer)
					if len(self.buffer) >= response_header['frag_len']:
						msg_data = self.buffer[:response_header['frag_len']]
						self.buffer = self.buffer[response_header['frag_len']:]
						return msg_data, err

				data, err = await asyncio.wait_for(self.connection.in_queue.get(), timeout = None)
				if err is not None:
					return None, err
				
				self.buffer += data
		
		except Exception as e:
			return None, e
		