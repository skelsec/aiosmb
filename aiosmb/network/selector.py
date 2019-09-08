from aiosmb.commons.smbtargetproxy import SMBTargetProxyServerType
from aiosmb.network.network import TCPSocket
from aiosmb.network.socks5network import Socks5ProxyConnection


class NetworkSelector:
    def __init__(self):
        pass

    @staticmethod
    def select(target):
        if target.proxy is None:
            return TCPSocket()
        elif target.proxy.proxy_type == SMBTargetProxyServerType.SOCKS5:
            return Socks5ProxyConnection()

        return None