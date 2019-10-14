import enum
import asyncio

from aiosmb import logger
from aiosmb.exceptions import *
from aiosmb.network.netbios import NetBIOSTransport
from aiosmb.smbconnection_server import SMBServerConnection

class TCPClient:
	def __init__(self, raddr, rport, reader, writer):
		self.raddr = raddr
		self.rport = rport
		self.reader = reader
		self.writer = writer
		self.out_queue = asyncio.Queue()
		self.in_queue = asyncio.Queue()

class TCPServerSocket:
	"""
	Generic asynchronous TCP socket class, nothing SMB related.
	Creates the connection and channels incoming/outgoing bytes via asynchonous queues.
	"""
	def __init__(self, ip, server_settings, port = 445,  shutdown_evt = asyncio.Event(), socket = None):
		self.ip = ip
		self.port = port
		self.server_settings = server_settings
		self.socket = socket #for future, if we want a custom soscket
		
		self.disconnected = asyncio.Event()
		self.shutdown_evt = shutdown_evt
		
	async def handle_incoming(self, client):
		"""
		Reads data bytes from the socket and dispatches it to the incoming queue
		"""
		while not self.shutdown_evt.is_set():			
			data = await asyncio.gather(*[client.reader.read(4096)], return_exceptions = True)
			
			if isinstance(data[0], bytes):
				await client.in_queue.put(data[0])
			
			elif isinstance(data[0], asyncio.CancelledError):
				return
				
			elif isinstance(data[0], Exception):
				logger.exception('[TCPSocket] handle_incoming %s' % str(data[0]))
				return
		
	async def handle_outgoing(self, client):
		"""
		Reads data bytes from the outgoing queue and dispatches it to the socket
		"""
		try:
			while not self.shutdown_evt.is_set():
				data = await client.out_queue.get()
				client.writer.write(data)
				await client.writer.drain()
		except asyncio.CancelledError:
			#the SMB connection is terminating
			return
			
		except Exception as e:
			logger.exception('[TCPSocket] handle_outgoing %s' % str(e))
		
	async def handle_client(self, reader, writer):
		raddr, rport = writer.get_extra_info('peername')
		logger.info('TCP client connected from %s:%s' % (raddr, rport))
		
		client = TCPClient(raddr, rport, reader, writer)
		asyncio.ensure_future(self.handle_outgoing(client))
		asyncio.ensure_future(self.handle_incoming(client))
		nbtransport = NetBIOSTransport(client)
		server = SMBServerConnection(self.server_settings, nbtransport)
		
		await nbtransport.run()
		await server.main()
		logger.info('SMB server terminated, closing client! %s:%s' % (raddr, rport))
		
		
	async def listen(self):
		server = await asyncio.start_server(self.handle_client, self.ip, self.port)
		addr = server.sockets[0].getsockname()
		async with server:
			logger.info('TCP Server in listening state')
			await server.serve_forever()
		logger.info('TCP server terminated')	
			
	async def run(self):
		return self.listen()
		