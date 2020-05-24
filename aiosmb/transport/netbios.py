import asyncio
import io

from aiosmb import logger
from aiosmb.protocol.smb.message import *
from aiosmb.protocol.smb2.message import *

class NetBIOSTransport:
	"""
	Converts incoming bytestream from the network starsport to SMB messages and vice-versa.
	This layer is presented so the network transport can be changed for a TCP/UDP/whatever type of transport.
	"""
	def __init__(self, network_transport):
		self.network_transport = network_transport
		self.socket_out_queue = network_transport.out_queue
		self.socket_in_queue = network_transport.in_queue
		
		self.in_queue = asyncio.Queue()
		self.out_queue = asyncio.Queue()
		
		self.outgoing_task = None
		self.incoming_task = None
		
	async def stop(self):
		"""
		Stops the input output processing
		"""
		if self.outgoing_task is not None:
			self.outgoing_task.cancel()
		if self.incoming_task is not None:
			self.incoming_task.cancel()
		
		
	async def run(self):
		"""
		Starts the input and output processing
		"""
		try:
			self.incoming_task = asyncio.create_task(self.handle_incoming())
			self.outgoing_task = asyncio.create_task(self.handle_outgoing())
			return True, None
		except Exception as e:
			return False, e
		
	async def parse_buffer(self, buffer, total_size = None):
		"""
		Parses the incoming bytes buffer, dispatches SMBv1 or SMBv2 messages to the in_queue
		Returns a bytes array with the remaining data
		"""
		if len(buffer) > 4:
			if not total_size:
				total_size = int.from_bytes(buffer[1:4], byteorder='big', signed = False) + 4
			
			if len(buffer) >= total_size:
				msg_data = buffer[:total_size][4:]
				buffer = buffer[total_size:]
				total_size = None
					
				#print('%s nbmsg! ' % (self.network_transport.writer.get_extra_info('peername')[0], ))
				#print('[NetBIOS] MSG dispatched')
				await self.in_queue.put( (msg_data, None) )
				await self.parse_buffer(buffer, total_size)
		
		return buffer
		
	async def handle_incoming(self):
		"""
		Reads data bytes from the socket_in_queue and parses the NetBIOS messages and the SMBv1/2 messages.
		Dispatches the SMBv1/2 message objects.
		"""
		try:
			buffer = b''
			while True:
				data, err = await self.socket_in_queue.get()
				if err is not None:
					raise err
				#parse
				buffer += data
				buffer = await self.parse_buffer(buffer)

		except asyncio.CancelledError:
			#the SMB connection is terminating
			return
			
		except Exception as e:
			logger.exception('NetBIOSTransport handle_incoming error')
			await self.in_queue.put( (None, e) )
			await self.stop()
		
	async def handle_outgoing(self):
		"""
		Reads SMBv1/2 outgoing message data bytes from out_queue, wraps them in NetBIOS object, then serializes them, then sends them to socket_out_queue
		"""
		try:
			while True:
				smb_msg_data = await self.out_queue.get()
				data  = b'\x00'
				data += len(smb_msg_data).to_bytes(3, byteorder='big', signed = False)
				data += smb_msg_data
				await self.socket_out_queue.put(data)
		
		except asyncio.CancelledError:
			#the SMB connection is terminating
			return
		
		except Exception as e:
			logger.exception('NetBIOSTransport handle_outgoing')
			await self.stop()
			