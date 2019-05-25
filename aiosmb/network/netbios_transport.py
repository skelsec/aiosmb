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
	def __init__(self, network_transport, shutdown_evt = asyncio.Event()):
		self.network_transport = network_transport
		self.socket_out_queue = network_transport.out_queue
		self.socket_in_queue = network_transport.in_queue
		
		self.in_queue = asyncio.Queue()
		self.out_queue = asyncio.Queue()
		
		self.shutdown_evt = shutdown_evt
		self.stop_evt = asyncio.Event()
		
	async def stop(self):
		"""
		Stops the input output processing
		"""
		self.stop_evt.set()
		self.in_queue = None
		self.out_queue = None
		
		
	async def run(self):
		"""
		Starts the input and output processing
		"""
		asyncio.ensure_future(self.handle_incoming())
		asyncio.ensure_future(self.handle_outgoing())
		
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
				
				if msg_data[0] == 0xFF:
					#version1
					msg = SMBMessage.from_bytes(msg_data)
				elif msg_data[0] == 0xFE:
					#version2
					msg = SMB2Message.from_bytes(msg_data)
				elif msg_data[0] == 0xFD:
					#encrypted transform
					msg = SMB2Transform.from_bytes(msg_data)
				elif msg_data[0] == 0xFC:
					#compressed transform
					msg = SMB2Transform.from_bytes(msg_data)
				else:
					raise Exception('Unknown SMB version!')
					
				await self.in_queue.put(msg)
				await self.parse_buffer(buffer, total_size)
		
		return buffer
		
	async def handle_incoming(self):
		"""
		Reads data bytes from the socket_in_queue and parses the NetBIOS messages and the SMBv1/2 messages.
		Dispatches the SMBv1/2 message objects.
		"""
		try:
			buffer = b''
			while not self.shutdown_evt.is_set() or not self.stop_evt.is_set():
				data = await self.socket_in_queue.get()
				#parse
				buffer += data
				buffer = await self.parse_buffer(buffer)
		except asyncio.CancelledError:
			#the SMB connection is terminating
			return
			
		except Exception as e:
			logger.exception('NetBIOSTransport handle_incoming')
			await self.stop()
		
	async def handle_outgoing(self):
		"""
		Reads SMBv1/2 outgoing message objects from out_queue, wraps them in NetBIOS object, then serializes them, then sends them to socket_out_queue
		"""
		try:
			while not self.shutdown_evt.is_set() or not self.stop_evt.is_set():
				smb_msg = await self.out_queue.get()
				#print(smb_msg)
				smb_msg_data = smb_msg.to_bytes()
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
			