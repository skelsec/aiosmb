import enum
import asyncio
import ipaddress
import copy

from aiosmb import logger
from aiosmb.commons.exceptions import *
from aiosmb.commons.connection.proxy import SMBProxy, SMBProxyType
from aiosmb.network.socks5 import Socks5ProxyConnection



class MultiplexorProxyConnection:
	"""
	"""
	def __init__(self, target):
		self.target = target
		
	async def connect(self):
		"""
		
		"""
		#hiding the import, so you'll only need to install multiplexor when actually using it
		from multiplexor.operator import MultiplexorOperator


		#creating connection string
		if self.target.proxy.type == SMBProxyType.MULTIPLEXOR:
			con_str = 'ws://%s:%s' % (self.target.proxy.ip, self.target.proxy.port)
		else:
			con_str = 'wss://%s:%s' % (self.target.proxy.ip, self.target.proxy.port)
		#creating operator and connecting to multiplexor server
		self.operator = MultiplexorOperator(con_str, logging_sink = logger)
		await self.operator.connect()
		#creating socks5 proxy
		server_info = await self.operator.start_socks5(self.target.proxy.agent_id)
		print(server_info)

		#copying the original target, then feeding it to socks5proxy object. it will hold the actual socks5 proxy server address we created before
		tp = SMBProxy()
		tp.ip = server_info['listen_ip']
		tp.port = server_info['listen_port']
		tp.timeout = self.target.proxy.timeout
		tp.type = SMBProxyType.SOCKS5

		newtarget = copy.deepcopy(self.target)
		newtarget.proxy = tp

		return Socks5ProxyConnection(target = newtarget)
