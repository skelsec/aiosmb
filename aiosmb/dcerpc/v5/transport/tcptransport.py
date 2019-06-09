import asyncio

from aiosmb import logger
from aiosmb.filereader import SMBFileReader
from aiosmb.dcerpc.v5.transport.common import *

class DCERPCTCPConnection:
	def __init__(self, ip, port):
		self.ip = ip
		self.port = port
		self.timeout = 2
		
		self.in_queue = asyncio.Queue()
		self.out_queue = asyncio.Queue()
		
		
		self.disconnected = asyncio.Event()
		self.shutdown_evt = asyncio.Event()
		
		
	async def handle_incoming(self):
		"""
		Reads data bytes from the socket and dispatches it to the incoming queue
		"""
		try:
			while not self.disconnected.is_set() or not self.shutdown_evt.is_set():
				data = await self.reader.read(4096)
				await self.in_queue.put(data)
		
		except asyncio.CancelledError:
			#the SMB connection is terminating
			return
			
		except Exception as e:	
			logger.exception('[DCERPCTCPConnection] handle_incoming %s' % str(e))
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
		
		asyncio.ensure_future(self.handle_incoming())
		asyncio.ensure_future(self.handle_outgoing())
		return
		
	async def disconnect(self):
		"""
		Disconnects from the socket.
		Stops the reader and writer streams.
		"""
		self.reader = None
		try:
			self.writer.close()
		except:
			pass
		self.writer = None
		self.disconnected.set()
		

class TCPTransport(DCERPCTransport):
	def __init__(self, connection, remote_name, dstport = 135):
		DCERPCTransport.__init__(self, connection, remote_name, dstport)
		self.transport_type = 'TCP'
		self.address = remote_name
		self.port = dstport
		
		self.connection = DCERPCTCPConnection(remote_name, dstport)
		self.buffer = b''
		self.data_in_evt = asyncio.Event()

	async def __handle_incoming(self):
		while True:
			data = await self.connection.in_queue.get()
			self.buffer += data
			self.data_in_evt.set()
		
	async def connect(self):
		asyncio.ensure_future(self.__handle_incoming())
		await self.connection.connect()
		
		return 1
	
	async def disconnect(self):
		try:
			await self.connection.close()
		except:
			pass
		
	async def send(self, data, forceWriteAndx = 0, forceRecv = 0):
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
	
	async def recv(self, count, forceRecv = 0):
		while len(self.buffer) < count:
			self.data_in_evt.clear()
			await self.data_in_evt.wait()
			
		data = self.buffer[:count]
		self.buffer = self.buffer[count:]
		return data
		