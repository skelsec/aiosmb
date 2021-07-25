import enum
import asyncio
import ssl

from aiosmb import logger
from aiosmb.commons.exceptions import *

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, QuicEvent, StreamDataReceived
from typing import Optional, cast


class QuicTransportClient(QuicConnectionProtocol):
	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)
		self._ack_waiter: Optional[asyncio.Future[None]] = None
		self.in_queue: asyncio.Queue = None
		self.disconnected_evt = None
		self.stream_id = None

	def connection_made(self, transport: asyncio.BaseTransport) -> None:
		print('Connected!')
		return super().connection_made(transport)

	async def send(self, data:bytes) -> None:
		if self.stream_id is None:
			self.stream_id = self._quic.get_next_available_stream_id()
		#logger.debug(f"Stream ID: {self.stream_id}")
		#print('Sending -> %s' % data)
		end_stream = False
		self._quic.send_stream_data(self.stream_id, data, end_stream)
		self.transmit()


	def quic_event_received(self, event: QuicEvent) -> None:
		if isinstance(event, StreamDataReceived):
			self.in_queue.put_nowait( (event.data, None) )
		if isinstance(event, ConnectionTerminated):
			self.in_queue.put_nowait( (None, None) )
		
			

class QUICSocket:
	"""
	Generic asynchronous TCP socket class, nothing SMB related.
	Creates the connection and channels incoming/outgoing bytes via asynchonous queues.
	"""
	def __init__(self, socket = None, target = None):
		self.settings = target
		self.socket = socket #for future, if we want a custom soscket
		
		self.out_queue = asyncio.Queue()
		self.in_queue = asyncio.Queue()
		
		self.disconnected_evt = asyncio.Event()
		
	async def disconnect(self):
		"""
		Disconnects from the socket.
		Stops the reader and writer streams.
		"""
		if self.disconnected.is_set():
			return
		self.disconnected.set()
	
	async def run_inner(self):
		try:
			async with connect(self.settings.hostname, self.settings.port, configuration=self.configuration, create_protocol=QuicTransportClient) as client:
				client = cast(QuicTransportClient, client)
				client.in_queue = self.in_queue
				client.disconnected_evt = self.disconnected_evt
				while not self.disconnected.is_set():
					data = await self.out_queue.get()
					await client.send(data)
		except asyncio.CancelledError:
			#the SMB connection is terminating
			return
			
		except Exception as e:
			logger.exception('[QUICSocket] handle_outgoing')
			await self.disconnect()

			
		
	#async def connect(self, settings): #not needed parameter because we have networkselector now...
	async def connect(self):
		"""
		Main function to be called, connects to the target specified in settings, and starts reading/writing.
		"""

		#self.settings = settings
		
		try:
			self.configuration = QuicConfiguration(
				alpn_protocols=['smb'], 
				is_client=True, 
				max_datagram_frame_size=65536, 
				verify_mode = ssl.CERT_NONE,
			)

			self.client = asyncio.create_task(self.run_inner())

			return True, None
		except Exception as e:
			logger.exception('[QUICSocket] main')
			return False, e

			
			