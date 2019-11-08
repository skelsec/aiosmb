
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
from aiosmb.network.proxies.socks5 import SOCKS5Method, SOCKS5Nego, SOCKS5NegoReply, SOCKS5Command, SOCKS5Request, SOCKS5ReplyType, SOCKS5Reply, SOCKS5PlainAuth

class Socks5ProxyConnection:
	"""
	Generic asynchronous TCP socket class, nothing SMB related.
	Creates the connection and channels incoming/outgoing bytes via asynchonous queues.
	"""
	def __init__(self, target = None, socket = None):
		self.target = target
		self.socket = socket #for future, if we want a custom soscket
		self.reader = None
		self.writer = None
		
		self.out_queue = asyncio.Queue()
		self.in_queue = asyncio.Queue()
		
		self.disconnected = asyncio.Event()

		self.incoming_task = None
		self.outgoing_task = None
		
	async def disconnect(self):
		"""
		Disconnects from the socket.
		Stops the reader and writer streams.
		"""
		if self.outgoing_task is not None:
			self.outgoing_task.cancel()
		if self.incoming_task is not None:
			self.incoming_task.cancel()

		if self.writer is not None:
			try:
				self.writer.close()
			except:
				pass
		self.writer = None
		self.reader = None
		self.disconnected.set()

	async def handle_incoming(self):
		"""
		Reads data bytes from the socket and dispatches it to the incoming queue
		"""
		try:
			timeout = int(self.target.proxy.timeout)
			while not self.disconnected.is_set():			
				data = await asyncio.gather(*[asyncio.wait_for(self.reader.read(4096), timeout)], return_exceptions = True)
				if isinstance(data[0], bytes):
					if data[0] == b'':
						await self.in_queue.put( (None, Exception('Socks5 server terminated the connection!')) )
						await self.disconnect()
					#print('%s : %s' % (self.writer.get_extra_info('peername')[0], data[0]))
					#print('SOCKS5 data in %s' % data[0])
					await self.in_queue.put( (data[0], None) )
				
				elif isinstance(data[0], asyncio.CancelledError):
					#print('SOCKS5 data in CANCELLED')
					return
					
				elif isinstance(data[0], Exception):
					#print('SOCKS5 data in exception')
					logger.exception('[SOCKS5] handle_incoming %s' % str(data[0]))
					await self.in_queue.put( (None, data[0]) )
					await self.disconnect()
					return
			
			#print('SOCKS5 data in EXITING')
		except asyncio.CancelledError:
			await self.in_queue.put( (None, asyncio.CancelledError) )
			return

		except Exception as e:
			import traceback
			traceback.print_exc()
			#print('SOCKS5 data in ERROR!')
			await self.in_queue.put( (None, e) )
			return

	async def handle_outgoing(self):
		"""
		Reads data bytes from the outgoing queue and dispatches it to the socket
		"""
		try:
			while not self.disconnected.is_set():
				data = await self.out_queue.get()
				#print('SOCKS5 data out %s' % data)
				self.writer.write(data)
				await self.writer.drain()
		except asyncio.CancelledError:
			#the SMB connection is terminating
			return
			
		except Exception as e:
			logger.exception('[SOCKS5] handle_outgoing %s' % str(e))
			await self.disconnect()
			
		
	async def connect(self):
		"""
		Main function to be called, connects to the target specified in target, and starts reading/writing.
		"""
		con = asyncio.open_connection(self.target.proxy.ip, int(self.target.proxy.port))
		try:
			self.proxy_reader, self.proxy_writer = await asyncio.wait_for(con, int(self.target.proxy.timeout))
		except asyncio.TimeoutError:
			logger.debug('[Socks5Proxy] Proxy Connection timeout')
			raise SMBConnectionTimeoutException()
			
		except ConnectionRefusedError:
			logger.debug('[Socks5Proxy] Proxy Connection refused')
			raise SMBConnectionRefusedException()
			
		except asyncio.CancelledError:
			#the SMB connection is terminating
			raise asyncio.CancelledError
			
		except Exception as e:
			logger.debug('[Socks5Proxy] connect generic exception')
			raise e

		
		#logger.info('Establishing proxy connection %s => %s' % (server.get_paddr(), target.get_paddr()))
		authmethods = [SOCKS5Method.NOAUTH]
		if self.target.proxy.username is not None:
			authmethods.append(SOCKS5Method.PLAIN)
		
		try:
			#logger.debug('Sending negotiation command to %s:%d' % proxy_writer.get_extra_info('peername'))
			self.proxy_writer.write(SOCKS5Nego.construct(authmethods).to_bytes())
			await asyncio.wait_for(self.proxy_writer.drain(), timeout = int(self.target.proxy.timeout))

			rep_nego = await asyncio.wait_for(SOCKS5NegoReply.from_streamreader(self.proxy_reader), timeout = int(self.target.proxy.timeout))
			logger.debug('Got negotiation reply from %s: %s' % (self.proxy_writer.get_extra_info('peername'), repr(rep_nego)))
			
			if rep_nego.METHOD == SOCKS5Method.PLAIN:
				logger.debug('Preforming plaintext auth to %s:%d' % self.proxy_writer.get_extra_info('peername'))
				self.proxy_writer.write(SOCKS5PlainAuth.construct(self.target.proxy.username, self.target.proxy.secret).to_bytes())
				await asyncio.wait_for(self.proxy_writer.drain(), timeout=int(self.target.proxy.timeout))
				rep_auth_nego = await asyncio.wait_for(SOCKS5NegoReply.from_streamreader(self.proxy_reader), timeout = int(self.target.proxy.timeout))

				if rep_auth_nego.METHOD != SOCKS5Method.NOAUTH:
					raise Exception('Failed to connect to proxy %s:%d! Authentication failed!' % self.proxy_writer.get_extra_info('peername'))

			logger.debug('Sending connect request to %s:%d' % self.proxy_writer.get_extra_info('peername'))
			self.proxy_writer.write(SOCKS5Request.construct(SOCKS5Command.CONNECT, self.target.get_hostname_or_ip(), int(self.target.port)).to_bytes())
			await asyncio.wait_for(self.proxy_writer.drain(), timeout=int(self.target.proxy.timeout))

			rep = await asyncio.wait_for(SOCKS5Reply.from_streamreader(self.proxy_reader), timeout=int(self.target.proxy.timeout))
			if rep.REP != SOCKS5ReplyType.SUCCEEDED:
				logger.info('Failed to connect to proxy %s! Server replied: %s' % (self.proxy_writer.get_extra_info('peername'), repr(rep.REP)))
				raise SMBSocks5ConnectionError('Socks5 remote end failed to connect to target! Reson: %s' % rep.REP.name)
			
			logger.debug('Server reply from %s : %s' % (self.proxy_writer.get_extra_info('peername'),repr(rep)))
		
		except asyncio.TimeoutError:
			logger.debug('[Socks5Proxy] Proxy Connection timeout')
			raise SMBConnectionTimeoutException()
		
		except asyncio.CancelledError:
			#the SMB connection is terminating
			raise asyncio.CancelledError
				
		except Exception as e:
			raise SMBSocks5ConnectionError('Error happened while establighing socket. Reson: %s' % e)
			logger.debug('[Socks5Proxy] connect generic exception')
			raise e
		
		else:
			logger.debug('Same socket can be used now on %s:%d' % (self.proxy_writer.get_extra_info('peername')))
			#this means that the communication can continue on the same socket!
			logger.info('Proxy connection succeeded')
			self.reader = self.proxy_reader
			self.writer = self.proxy_writer
			self.incoming_task = asyncio.create_task(self.handle_incoming())
			self.outgoing_task = asyncio.create_task(self.handle_outgoing())
			return

			

			


			