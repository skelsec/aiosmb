import asyncio

class TCPSocket:
	"""
	Generic asynchronous TCP socket class, nothing SMB related.
	Creates the connection and channels incoming/outgoing bytes via asynchonous queues.
	"""
	def __init__(self, shutdown_evt = asyncio.Event(), socket = None):
		self.settings = None
		self.socket = socket #for future, if we want a custom soscket
		self.reader = None
		self.writer = None
		
		self.out_queue = asyncio.Queue()
		self.in_queue = asyncio.Queue()
		
		self.disconnected = asyncio.Event()
		self.shutdown_evt = shutdown_evt
		
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
		
	async def handle_incoming(self):
		"""
		Reads data bytes from the socket and dispatches it to the incoming queue
		"""
		try:
			while not self.disconnected.is_set() or not self.shutdown_evt.is_set():
				data = await self.reader.read(4096)
				await self.in_queue.put(data)				
		except Exception as e:
			await self.disconnect()
			print('[TCPSocket] %s' % e)
		
	async def handle_outgoing(self):
		"""
		Reads data bytes from the outgoing queue and dispatches it to the socket
		"""
		try:
			while not self.disconnected.is_set() or not self.shutdown_evt.is_set():
				data = await self.out_queue.get()
				print(data)
				self.writer.write(data)
				await self.writer.drain()
		except Exception as e:
			await self.disconnect()
			print('[TCPSocket] %s' % e)
		
	async def connect(self, settings):
		"""
		Main function to be called, connects to the target specified in settings, and starts reading/writing.
		"""
		try:
			self.settings = settings
			self.reader, self.writer = await asyncio.open_connection(self.settings.get_ip(), self.settings.get_port())
			asyncio.ensure_future(self.handle_incoming())
			asyncio.ensure_future(self.handle_outgoing())
			return			
		except Exception as e:
			await self.disconnect()
			print('[TCPSocket] %s' % e)