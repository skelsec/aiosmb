from aiosmb.commons.connection.proxy import SMBProxyType
from aiosmb.network.tcp import TCPSocket
from aiosmb.network.socks import SocksProxyConnection
from aiosmb.network.multiplexornetwork import MultiplexorProxyConnection



class NetworkSelector:
	def __init__(self):
		pass

	@staticmethod
	async def select(target):
		if target.proxy is None:
			return TCPSocket(target = target), None
		elif target.proxy.type in [SMBProxyType.WSNET,SMBProxyType.WSNETWS, SMBProxyType.WSNETWSS, SMBProxyType.SOCKS5, SMBProxyType.SOCKS5_SSL, SMBProxyType.SOCKS4, SMBProxyType.SOCKS4_SSL]:
			return SocksProxyConnection(target = target), None

		elif target.proxy.type in [SMBProxyType.MULTIPLEXOR, SMBProxyType.MULTIPLEXOR_SSL]:
			mpc = MultiplexorProxyConnection(target)
			socks_proxy, err = await mpc.connect()
			return socks_proxy, err

		else:
			return None, Exception('Cant select correct connection type!')