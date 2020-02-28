#https://www.ietf.org/rfc/rfc1928.txt
#https://tools.ietf.org/html/rfc1929
#https://tools.ietf.org/html/rfc1961

import io
import enum
import ipaddress
import socket
import asyncio

async def readexactly_or_exc(reader, n, timeout = None):
	"""
	Helper function to read exactly N amount of data from the wire.
	:param reader: The reader object
	:type reader: asyncio.StreamReader
	:param n: The maximum amount of bytes to read.
	:type n: int
	:param timeout: Time in seconds to wait for the reader to return data
	:type timeout: int
	:return: bytearray
	"""
	temp = await asyncio.gather(*[asyncio.wait_for(reader.readexactly(n), timeout = timeout)], return_exceptions=True)
	if isinstance(temp[0], bytes):
		return temp[0]
	else:
		raise temp[0]


async def read_or_exc(reader, n, timeout = None):
	"""
	Helper function to read N amount of data from the wire.
	:param reader: The reader object
	:type reader: asyncio.StreamReader
	:param n: The maximum amount of bytes to read. BEWARE: this only sets an upper limit of the data to be read
	:type n: int
	:param timeout: Time in seconds to wait for the reader to return data
	:type timeout: int
	:return: bytearray
	"""

	temp = await asyncio.gather(*[asyncio.wait_for(reader.read(n), timeout = timeout)], return_exceptions=True)
	if isinstance(temp[0], bytes):
		return temp[0]
	else:
		raise temp[0]


class SOCKS5ServerState(enum.Enum):
	NEGOTIATION = 0
	NOT_AUTHENTICATED = 1
	REQUEST = 3 
	RELAYING = 4


class SOCKS5Method(enum.Enum):
	NOAUTH = 0x00
	GSSAPI = 0x01
	PLAIN  = 0x02
	# IANA ASSIGNED X'03' to X'7F'
	# RESERVED FOR PRIVATE METHODS X'80' to X'FE'

	NOTACCEPTABLE = 0xFF


class SOCKS5Command(enum.Enum):
	CONNECT = 0x01
	BIND = 0x02
	UDP_ASSOCIATE = 0x03


class SOCKS5AddressType(enum.Enum):
	IP_V4 = 0x01
	DOMAINNAME = 0x03
	IP_V6 = 0x04


class SOCKS5ReplyType(enum.Enum):
	SUCCEEDED = 0X00 # o  X'00' succeeded
	FAILURE = 0x01 # o  X'01' general SOCKS server failure
	CONN_NOT_ALLOWED = 0x02#         o  X'02' connection not allowed by ruleset
	NETWORK_UNREACHABLE = 0x03 #o  X'03' Network unreachable
	HOST_UNREACHABLE = 0x04#o  X'04' Host unreachable
	CONN_REFUSED = 0x05 #o  X'05' Connection refused
	TTL_EXPIRED = 0x06 #o  X'06' TTL expired
	COMMAND_NOT_SUPPORTED = 0x07 #o  X'07' Command not supported
	ADDRESS_TYPE_NOT_SUPPORTED = 0x08 #o  X'08' Address type not supported
	#o  X'09' to X'FF' unassigned


class SOCKS5SocketParser:
	def __init__(self, protocol = socket.SOCK_STREAM):
		self.protocol = protocol

	def parse(self, soc, packet_type):
		return packet_type.from_bytes(self.read_soc(soc, packet_type.size))

	def read_soc(self, soc, size):
		data = b''
		while True:
			temp = soc.recv(4096)
			if temp == '':
				break
			data += temp
			if len(data) == size:
				break
		return data


class SOCKS5CommandParser:
	# the reason we need this class is: SOCKS5 protocol messages doesn't have a type field,
	# the messages are parsed in context of the session itself.
	def __init__(self, protocol = socket.SOCK_STREAM):
		self.protocol = protocol #not used atm

	def parse(self, buff, session):
		if session.current_state == SOCKS5ServerState.NEGOTIATION:
			return SOCKS5Nego.from_buffer(buff)
		
		if session.current_state == SOCKS5ServerState.NOT_AUTHENTICATED:
			if session.mutual_auth_type == SOCKS5Method.PLAIN:
				return SOCKS5PlainAuth.from_buffer(buff)
			else:
				raise Exception('Not implemented!')

		if session.current_state == SOCKS5ServerState.REQUEST:
			return SOCKS5Request.from_buffer(buff)

	@staticmethod
	async def from_streamreader(reader, session, timeout = None):
		if session.current_state == SOCKS5ServerState.NEGOTIATION:
			t = await asyncio.wait_for(SOCKS5Nego.from_streamreader(reader), timeout = timeout)
			return t
		
		if session.current_state == SOCKS5ServerState.NOT_AUTHENTICATED:
			if session.mutual_auth_type == SOCKS5Method.PLAIN:
				t = await asyncio.wait_for(SOCKS5PlainAuth.from_streamreader(reader), timeout = timeout)
				return t
			else:
				raise Exception('Not implemented!')

		if session.current_state == SOCKS5ServerState.REQUEST:
			t = await asyncio.wait_for(SOCKS5Request.from_streamreader(reader), timeout = timeout)
			return t


class SOCKS5AuthHandler:
	def __init__(self, authtype, creds = None):
		self.authtype  = authtype
		self.creds = creds

	def do_AUTH(self, msg):
		if self.authtype == SOCKS5Method.PLAIN:
			if not isinstance(msg, SOCKS5PlainAuth):
				raise Exception('Wrong message/auth type!')

			if self.creds is None:
				return True, SOCKS5PlainCredentials(msg.UNAME, msg.PASSWD)
			else:
				if msg.UNAME in self.creds:
					if msg.PASSWD == self.creds[msg.UNAME]:
						return True, SOCKS5PlainCredentials(msg.UNAME, msg.PASSWD)

				return False, SOCKS5PlainCredentials(msg.UNAME, msg.PASSWD)

		elif self.authtype == SOCKS5Method.GSSAPI:
			raise Exception('Not implemented! yet')
		
		else:
			raise Exception('Not implemented!')


class SOCKS5PlainCredentials:
	def __init__(self, username, password):
		self.username = username
		self.password = password


class SOCKS5PlainAuth:
	def __init__(self):
		self.VER = None
		self.ULEN = None
		self.UNAME = None
		self.PLEN = None
		self.PASSWD = None

	@staticmethod
	async def from_streamreader(reader, timeout = None):
		auth = SOCKS5PlainAuth()
		t = await read_or_exc(reader, 1, timeout = timeout)
		auth.VER = int.from_bytes(t, byteorder = 'big', signed = False)
		t = await read_or_exc(reader, 1, timeout = timeout)
		auth.ULEN = int.from_bytes(t, byteorder = 'big', signed = False)
		t = await read_or_exc(reader, auth.ULEN, timeout = timeout)
		auth.UNAME = t.decode()
		t = await read_or_exc(reader, 1, timeout = timeout)
		auth.PLEN = int.from_bytes(t, byteorder = 'big', signed = False)
		t = await read_or_exc(reader, auth.PLEN, timeout = timeout)
		auth.PASSWD = t.decode()

		return auth

	@staticmethod
	def from_bytes(bbuff):
		return SOCKS5PlainAuth.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		auth = SOCKS5PlainAuth()
		auth.VER = int.from_bytes(buff.read(1), byteorder = 'big', signed = False) 
		auth.ULEN = int.from_bytes(buff.read(1), byteorder = 'big', signed = False)
		auth.UNAME = buff.read(auth.ULEN).decode()
		auth.PLEN = int.from_bytes(buff.read(1), byteorder = 'big', signed = False)
		auth.PASSWD = buff.read(auth.PLEN).decode()

		return auth

	@staticmethod
	def construct(username, password):
		auth = SOCKS5PlainAuth()
		auth.VER    = 5
		auth.ULEN   = len(username)
		auth.UNAME  = username
		auth.PLEN   = len(password)
		auth.PASSWD = password

		return auth

	def to_bytes(self):
		t  = self.VER.to_bytes(1, byteorder = 'big', signed = False)
		t += self.ULEN.to_bytes(1, byteorder = 'big', signed = False)
		t += self.UNAME.encode()
		t += self.PLEN.to_bytes(1, byteorder = 'big', signed = False)
		t += self.PASSWD.encode()
		return t


class SOCKS5Nego:
	def __init__(self):
		self.VER = None
		self.NMETHODS = None
		self.METHODS = None

	@staticmethod
	async def from_streamreader(reader, timeout = None):
		nego = SOCKS5Nego()
		t = await read_or_exc(reader,1, timeout = timeout)
		nego.VER = int.from_bytes(t, byteorder = 'big', signed = False)
		t = await read_or_exc(reader,1, timeout = timeout)
		nego.NMETHODS = int.from_bytes(t, byteorder = 'big', signed = False)
		nego.METHODS = []
		for _ in range(nego.NMETHODS):
			t = await read_or_exc(reader,1, timeout = timeout)
			nego.METHODS.append(SOCKS5Method(int.from_bytes(t, byteorder = 'big', signed = False)))

		return nego

	@staticmethod
	def from_bytes(bbuff):
		return SOCKS5Nego.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		nego = SOCKS5Nego()
		nego.VER = int.from_bytes(buff.read(1), byteorder = 'big', signed = False) 
		nego.NMETHODS = int.from_bytes(buff.read(1), byteorder = 'big', signed = False) 
		nego.METHODS = []
		for _ in range(nego.NMETHODS):
			nego.METHODS.append(SOCKS5Method(int.from_bytes(buff.read(1), byteorder = 'big', signed = False)))
		return nego

	@staticmethod
	def construct(methods):
		if not isinstance(methods, list):
			methods = [methods]
		nego = SOCKS5Nego()
		nego.VER = 5
		nego.NMETHODS = len(methods)
		nego.METHODS = methods
		return nego

	def to_bytes(self):
		t  = self.VER.to_bytes(1, byteorder = 'big', signed = False)
		t += self.NMETHODS.to_bytes(1, byteorder = 'big', signed = False)
		for method in self.METHODS:
			t += method.value.to_bytes(1, byteorder = 'big', signed = False)
		return t

class SOCKS5NegoReply:
	def __init__(self):
		self.VER = None
		self.METHOD = None

	def __repr__(self):
		t  = '== SOCKS5NegoReply ==\r\n'
		t += 'VER: %s\r\n' % self.VER
		t += 'METHOD: %s\r\n' % self.METHOD
		return t

	@staticmethod
	def from_socket(soc):
		data = b''
		total_size = 2
		while True:
			temp = soc.recv(1024)
			if temp == b'':
				break
			data += temp
			if len(data) >= total_size:
				break
		return SOCKS5NegoReply.from_bytes(data)

	@staticmethod
	async def from_streamreader(reader, timeout = None):
		rep = SOCKS5NegoReply()
		t = await read_or_exc(reader,1, timeout = timeout)
		rep.VER = int.from_bytes(t, byteorder = 'big', signed = False)
		t = await read_or_exc(reader,1, timeout = timeout)
		rep.METHOD = SOCKS5Method(int.from_bytes(t, byteorder = 'big', signed = False))
		
		return rep

	@staticmethod
	def from_bytes(bbuff):
		return SOCKS5NegoReply.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		rep = SOCKS5NegoReply()
		rep.VER = int.from_bytes(buff.read(1), byteorder = 'big', signed = False)
		rep.METHOD = SOCKS5Method(int.from_bytes(buff.read(1), byteorder = 'big', signed = False))
		return rep

	@staticmethod
	def construct(method):
		rep = SOCKS5NegoReply()
		rep.VER = 5
		rep.METHOD = method
		return rep

	@staticmethod
	def construct_auth(method, ver = 1):
		rep = SOCKS5NegoReply()
		rep.VER = ver
		rep.METHOD = method
		return rep


	def to_bytes(self):
		t  = self.VER.to_bytes(1, byteorder = 'big', signed = False)
		t += self.METHOD.value.to_bytes(1, byteorder = 'big', signed = False)
		return t


class SOCKS5Request:
	def __init__(self):
		self.VER = None
		self.CMD = None
		self.RSV = None
		self.ATYP = None
		self.DST_ADDR = None
		self.DST_PORT = None

	@staticmethod
	async def from_streamreader(reader, timeout = None):
		req = SOCKS5Request()
		t = await read_or_exc(reader,1, timeout = timeout)
		req.VER = int.from_bytes(t, byteorder = 'big', signed = False)
		t = await read_or_exc(reader,1, timeout = timeout)
		req.CMD = SOCKS5Command(int.from_bytes(t, byteorder = 'big', signed = False))
		t = await read_or_exc(reader,1, timeout = timeout)
		req.RSV = int.from_bytes(t, byteorder = 'big', signed = False)
		t = await read_or_exc(reader,1, timeout = timeout)
		req.ATYP = SOCKS5AddressType(int.from_bytes(t, byteorder = 'big', signed = False))
		if req.ATYP == SOCKS5AddressType.IP_V4:
			t = await read_or_exc(reader,4, timeout = timeout)
			req.DST_ADDR = ipaddress.IPv4Address(t)
		elif req.ATYP == SOCKS5AddressType.IP_V6:
			t = await read_or_exc(reader,16, timeout = timeout)
			req.DST_ADDR = ipaddress.IPv6Address(t)

		elif req.ATYP == SOCKS5AddressType.DOMAINNAME:
			t = await read_or_exc(reader,1, timeout = timeout)
			length = int.from_bytes(t, byteorder = 'big', signed = False)
			t = await read_or_exc(reader,length, timeout = timeout)
			req.DST_ADDR = t.decode()

		t = await read_or_exc(reader,2, timeout = timeout)
		req.DST_PORT = int.from_bytes(t, byteorder = 'big', signed = False)

		return req

	@staticmethod
	def from_bytes(bbuff):
		return SOCKS5Request.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		req = SOCKS5Request()
		req.VER = int.from_bytes(buff.read(1), byteorder = 'big', signed = False)
		req.CMD = SOCKS5Command(int.from_bytes(buff.read(1), byteorder = 'big', signed = False))
		req.RSV = int.from_bytes(buff.read(1), byteorder = 'big', signed = False) 
		req.ATYP = SOCKS5AddressType(int.from_bytes(buff.read(1), byteorder = 'big', signed = False)) 
		if req.ATYP == SOCKS5AddressType.IP_V4:
			req.DST_ADDR = ipaddress.IPv4Address(buff.read(4))
		elif req.ATYP == SOCKS5AddressType.IP_V6:
			req.DST_ADDR = ipaddress.IPv6Address(buff.read(16))
		elif req.ATYP == SOCKS5AddressType.DOMAINNAME:
			length = int.from_bytes(buff.read(1), byteorder = 'big', signed = False) 
			req.DST_ADDR = buff.read(length).decode()

		req.DST_PORT = int.from_bytes(buff.read(2), byteorder = 'big', signed = False)
		return req

	@staticmethod
	def construct(cmd, address, port):
		req = SOCKS5Request()
		req.VER = 5
		req.CMD = cmd
		req.RSV = 0
		if isinstance(address, ipaddress.IPv4Address):
			req.ATYP = SOCKS5AddressType.IP_V4
			req.DST_ADDR = address
		elif isinstance(address, ipaddress.IPv6Address):
			req.ATYP = SOCKS5AddressType.IP_V6
			req.DST_ADDR = address
		elif isinstance(address, str):
			req.ATYP = SOCKS5AddressType.DOMAINNAME
			req.DST_ADDR = address

		req.DST_PORT = port
		return req

	def to_bytes(self):
		t  = self.VER.to_bytes(1, byteorder = 'big', signed = False)
		t += self.CMD.value.to_bytes(1, byteorder = 'big', signed = False)
		t += self.RSV.to_bytes(1, byteorder = 'big', signed = False)
		t += self.ATYP.value.to_bytes(1, byteorder = 'big', signed = False)
		if self.ATYP == SOCKS5AddressType.DOMAINNAME:
			t += len(self.DST_ADDR).to_bytes(1, byteorder = 'big', signed = False)
			t += self.DST_ADDR.encode()
		else:	
			t += self.DST_ADDR.packed
		t += self.DST_PORT.to_bytes(2, byteorder = 'big', signed = False)
		return t


class SOCKS5Reply:
	def __init__(self):
		self.VER = None
		self.REP = None
		self.RSV = None
		self.ATYP = None
		self.BIND_ADDR= None
		self.BIND_PORT= None

	@staticmethod
	def from_socket(soc):
		data = b''
		total_size = 1024
		while True:
			temp = soc.recv(1024)
			if temp == b'':
				break
			data += temp

			if len(data) > 4:
				rt = SOCKS5AddressType(data[3])
				if rt == SOCKS5AddressType.IP_V4:
					total_size = 4 + 2 + 4
				if rt == SOCKS5AddressType.IP_V6:
					total_size = 4 + 2 + 16
				if rt == SOCKS5AddressType.DOMAINNAME:
					total_size = 4 + 2 + data[4]
			if len(data) >= total_size:
				break

		return SOCKS5Reply.from_bytes(data)

	@staticmethod
	async def from_streamreader(reader, timeout = None):
		rep = SOCKS5Reply()
		t = await read_or_exc(reader,1, timeout = timeout)
		rep.VER = int.from_bytes(t, byteorder = 'big', signed = False)
		t = await read_or_exc(reader,1, timeout = timeout)
		rep.REP = SOCKS5ReplyType(int.from_bytes(t, byteorder = 'big', signed = False))
		t = await read_or_exc(reader,1, timeout = timeout)
		rep.RSV = int.from_bytes(t, byteorder = 'big', signed = False)
		t = await read_or_exc(reader,1, timeout = timeout)
		rep.ATYP = SOCKS5AddressType(int.from_bytes(t, byteorder = 'big', signed = False))
		if rep.ATYP == SOCKS5AddressType.IP_V4:
			t = await read_or_exc(reader,4, timeout = timeout)
			rep.BIND_ADDR = ipaddress.IPv4Address(t)
		elif rep.ATYP == SOCKS5AddressType.IP_V6:
			t = await read_or_exc(reader,16, timeout = timeout)
			rep.BIND_ADDR = ipaddress.IPv6Address(t)
		elif rep.ATYP == SOCKS5AddressType.DOMAINNAME:
			t = await read_or_exc(reader,1, timeout = timeout)
			length = int.from_bytes(t, byteorder = 'big', signed = False)
			t = await read_or_exc(reader,length, timeout = timeout)
			rep.BIND_ADDR = t.decode()

		t = await read_or_exc(reader,2, timeout = timeout)
		rep.BIND_PORT = int.from_bytes(t, byteorder = 'big', signed = False)
		return rep

	@staticmethod
	def from_bytes(bbuff):
		return SOCKS5Reply.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		rep = SOCKS5Reply()
		rep.VER = int.from_bytes(buff.read(1), byteorder = 'big', signed = False) 
		rep.REP = SOCKS5ReplyType(int.from_bytes(buff.read(1), byteorder = 'big', signed = False))
		rep.RSV = int.from_bytes(buff.read(1), byteorder = 'big', signed = False)
		rep.ATYP = SOCKS5AddressType(int.from_bytes(buff.read(1), byteorder = 'big', signed = False))

		if rep.ATYP == SOCKS5AddressType.IP_V4:
			rep.BIND_ADDR = ipaddress.IPv4Address(buff.read(4))
		elif rep.ATYP == SOCKS5AddressType.IP_V6:
			rep.BIND_ADDR = ipaddress.IPv6Address(buff.read(16))
		elif rep.ATYP == SOCKS5AddressType.DOMAINNAME:
			length = int.from_bytes(buff.read(1), byteorder = 'big', signed = False) 
			rep.BIND_ADDR = buff.read(length).decode()

		rep.BIND_PORT = int.from_bytes(buff.read(2), byteorder = 'big', signed = False)

		return rep

	@staticmethod
	def construct(reply, address, port): 
		rep = SOCKS5Reply()
		rep.VER = 5
		rep.REP = reply
		rep.RSV = 0
		if isinstance(address, ipaddress.IPv4Address):
			rep.ATYP = SOCKS5AddressType.IP_V4
			rep.DST_ADDR = address
		elif isinstance(address, ipaddress.IPv6Address):
			rep.ATYP = SOCKS5AddressType.IP_V6
			rep.DST_ADDR = address
		elif isinstance(address, str):
			rep.ATYP = SOCKS5AddressType.DOMAINNAME
			rep.DST_ADDR = address

		rep.DST_PORT = port
		return rep

	def to_bytes(self):
		t  = self.VER.to_bytes(1, byteorder = 'big', signed = False)
		t += self.REP.value.to_bytes(1, byteorder = 'big', signed = False)
		t += self.RSV.to_bytes(1, byteorder = 'big', signed = False)
		t += self.ATYP.value.to_bytes(1, byteorder = 'big', signed = False)
		if self.ATYP == SOCKS5AddressType.DOMAINNAME:
			t += len(self.DST_ADDR).to_bytes(1, byteorder = 'big', signed = False)
			t += self.DST_ADDR.encode()
		else:	
			t += self.DST_ADDR.packed
		t += self.DST_PORT.to_bytes(2, byteorder = 'big', signed = False)
		return t

	def __repr__(self):
		t  = '== SOCKS5Reply ==\r\n'
		t += 'REP: %s\r\n' % repr(self.REP)
		t += 'ATYP: %s\r\n' % repr(self.ATYP)
		t += 'BIND_ADDR: %s\r\n' % repr(self.BIND_ADDR)
		t += 'BIND_PORT: %s\r\n' % repr(self.BIND_PORT)

		return t


class SOCKS5UDP:
	def __init__(self):
		self.RSV = None
		self.FRAG = None
		self.ATYP = None
		self.DST_ADDR = None
		self.DST_PORT = None
		self.DATA = None

	@staticmethod
	async def from_streamreader(reader, timeout = None):
		rep = SOCKS5UDP()
		t = await read_or_exc(reader,2, timeout = timeout)
		rep.RSV = int.from_bytes(t, byteorder = 'big', signed = False)
		t = await read_or_exc(reader,1, timeout = timeout)
		rep.FRAG = SOCKS5ReplyType(int.from_bytes(t, byteorder = 'big', signed = False))
		t = await read_or_exc(reader,1, timeout = timeout)
		rep.ATYP = SOCKS5AddressType(int.from_bytes(t, byteorder = 'big', signed = False))
		if rep.ATYP == SOCKS5AddressType.IP_V4:
			t = await read_or_exc(reader,4, timeout = timeout)
			rep.DST_ADDR = ipaddress.IPv4Address(t)
		elif rep.ATYP == SOCKS5AddressType.IP_V6:
			t = await read_or_exc(reader,16, timeout = timeout)
			rep.DST_ADDR = ipaddress.IPv6Address(t)

		elif rep.ATYP == SOCKS5AddressType.DOMAINNAME:
			t = await read_or_exc(reader,1, timeout = timeout)
			length = int.from_bytes(t, byteorder = 'big', signed = False)
			t = await read_or_exc(reader,length, timeout = timeout)
			rep.DST_ADDR = t.decode()

		t = await read_or_exc(reader,2, timeout = timeout)
		rep.DST_PORT = int.from_bytes(t, byteorder = 'big', signed = False)
		return rep

	@staticmethod
	def from_bytes(bbuff):
		return SOCKS5UDP.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		rep = SOCKS5UDP()
		rep.RSV = int.from_bytes(buff.read(2), byteorder = 'big', signed = False)
		rep.FRAG = int.from_bytes(buff.read(1), byteorder = 'big', signed = False)
		rep.ATYP = SOCKS5AddressType(buff.read(1), byteorder = 'big', signed = False)
		if rep.ATYP == SOCKS5AddressType.IP_V4:
			rep.DST_ADDR = ipaddress.IPv4Address(buff.read(4))
		elif rep.ATYP == SOCKS5AddressType.IP_V6:
			rep.DST_ADDR = ipaddress.IPv6Address(buff.read(16))
		elif rep.ATYP == SOCKS5AddressType.DOMAINNAME:
			length = int.from_bytes(buff.read(1), byteorder = 'big', signed = False) 
			rep.DST_ADDR = buff.read(length).decode()

		rep.DST_PORT = int.from_bytes(buff.read(2), byteorder = 'big', signed = False)
		#be careful, not data length is defined in the RFC!!
		rep.DATA = buff.read()

	@staticmethod
	def construct(address, port, data, frag = 0):
		req = SOCKS5Request()
		req.RSV = 0
		req.FRAG = frag
		if isinstance(address, ipaddress.IPv4Address):
			req.ATYP = SOCKS5AddressType.IP_V4
			req.DST_ADDR = address
		elif isinstance(address, ipaddress.IPv6Address):
			req.ATYP = SOCKS5AddressType.IP_V6
			req.DST_ADDR = address
		elif isinstance(address, str):
			req.ATYP = SOCKS5AddressType.DOMAINNAME
			req.DST_ADDR = address

		req.DST_PORT = port
		req.DATA = data
		return req

	def to_bytes(self):
		t  = self.RSV.to_bytes(2, byteorder = 'big', signed = False)
		t += self.FRAG.value.to_bytes(1, byteorder = 'big', signed = False)
		t += self.ATYP.value.to_bytes(1, byteorder = 'big', signed = False)
		if self.ATYP == SOCKS5AddressType.DOMAINNAME:
			t += len(self.DST_ADDR).to_bytes(1, byteorder = 'big', signed = False)
			t += self.DST_ADDR.encode()
		else:	
			t += self.DST_ADDR.packed
		t += self.DST_PORT.to_bytes(2, byteorder = 'big', signed = False)
		t += self.DATA
		return t