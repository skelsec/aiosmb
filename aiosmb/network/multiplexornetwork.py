import enum
import asyncio
import ipaddress
import copy

from aiosmb import logger
from aiosmb.exceptions import *
from aiosmb.commons.connection.targetproxy import SMBTargetProxy, SMBTargetProxyServerType
from aiosmb.network.socks5network import Socks5ProxyConnection

from multiplexor.operator import MultiplexorOperator

class MultiplexorProxyConnection:
	"""
	"""
	def __init__(self, target):
		self.target = target
		
	async def connect(self):
		"""
		
		"""
		#creating connection string
		if self.target.proxy.type == SMBTargetProxyServerType.MULTIPLEXOR:
			con_str = 'ws://%s:%s' % (self.target.proxy.ip, self.target.proxy.port)
		else:
			con_str = 'wss://%s:%s' % (self.target.proxy.ip, self.target.proxy.port)
		#creating operator and connecting to multiplexor server
		self.operator = MultiplexorOperator(con_str)
		await self.operator.connect()
		#creating socks5 proxy
		server_info = await self.operator.start_socks5(self.target.proxy.agent_id)
		print(server_info)

		#copying the original target, then feeding it to socks5proxy object. it will hold the actual socks5 proxy server address we created before
		tp = SMBTargetProxy()
		tp.ip = server_info['listen_ip']
		tp.port = server_info['listen_port']
		tp.timeout = self.target.proxy.timeout
		tp.type = SMBTargetProxyServerType.SOCKS5

		newtarget = copy.deepcopy(self.target)
		newtarget.proxy = tp

		return Socks5ProxyConnection(target = newtarget)
