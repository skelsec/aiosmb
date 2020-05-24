import enum
import asyncio
import ipaddress
import copy

from asysocks.common.clienturl import SocksClientURL 
from asysocks.common.constants import SocksServerVersion, SocksProtocol, SOCKS5Method
from asysocks.common.target import SocksTarget

from aiosmb import logger
from aiosmb.commons.exceptions import *
from aiosmb.commons.connection.proxy import SMBProxy, SMBProxyType
from aiosmb.network.socks import SocksProxyConnection
from minikerberos.common.target import KerberosTarget
from minikerberos.common.proxy import KerberosProxy



class MultiplexorProxyConnection:
	"""
	"""
	def __init__(self, target):
		self.target = target
		
	async def connect(self, is_kerberos = False):
		"""
		
		"""
		try:
			#hiding the import, so you'll only need to install multiplexor when actually using it
			from multiplexor.operator import MultiplexorOperator
			

			#creating connection string
			#if self.target.proxy.type == SMBProxyType.MULTIPLEXOR:
			#	con_str = 'ws://%s:%s' % (self.target.proxy.ip, self.target.proxy.port)
			#else:
			#	con_str = 'wss://%s:%s' % (self.target.proxy.ip, self.target.proxy.port)
			con_str = self.target.proxy.target.get_server_url()
			#creating operator and connecting to multiplexor server
			self.operator = MultiplexorOperator(con_str, logging_sink = logger)
			await self.operator.connect()
			#creating socks5 proxy
			server_info = await self.operator.start_socks5(self.target.proxy.target.agent_id)
			await self.operator.terminate()
			#print(server_info)
			if is_kerberos is False:
				
				#copying the original target, then feeding it to socks5proxy object. it will hold the actual socks5 proxy server address we created before
				tp = SMBProxy()
				tp.target = SocksTarget()
				tp.target.version = SocksServerVersion.SOCKS5
				tp.target.server_ip = server_info['listen_ip']
				tp.target.server_port = server_info['listen_port']
				tp.target.is_bind = False
				tp.target.proto = SocksProtocol.TCP
				tp.target.timeout = 10
				tp.target.buffer_size = 4096
				
				tp.target.endpoint_ip = self.target.ip
				tp.target.endpoint_port = self.target.port
				tp.target.endpoint_timeout = self.target.timeout
				tp.type = SMBProxyType.SOCKS5

				newtarget = copy.deepcopy(self.target)
				newtarget.proxy = tp

				

				return SocksProxyConnection(target = newtarget), None
			
			else:
				kt = copy.deepcopy(self.target)
				kt.proxy = KerberosProxy()
				kt.proxy.target = SocksTarget()
				kt.proxy.target.version = SocksServerVersion.SOCKS5
				kt.proxy.target.server_ip = server_info['listen_ip']
				kt.proxy.target.server_port = server_info['listen_port']
				kt.proxy.target.is_bind = False
				kt.proxy.target.proto = SocksProtocol.TCP
				kt.proxy.target.timeout = 10
				kt.proxy.target.buffer_size = 4096

				kt.proxy.target.endpoint_ip = self.target.ip
				kt.proxy.target.endpoint_port = self.target.port
				kt.proxy.creds = copy.deepcopy(self.target.proxy.auth)

				return kt, None

		except Exception as e:
			return None, e
