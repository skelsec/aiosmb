import asyncio
from asysocks.unicomm.client import UniClient
from asysocks.unicomm.common.packetizers import Packetizer
from aiosmb.dcerpc.v5.rpcrt import MSRPCRespHeader

class DCERPCPacketizer(Packetizer):
	def __init__(self, buffer_size = 65535):
		Packetizer.__init__(self, buffer_size)
		self.buffer_size = buffer_size
		self.in_buffer = b''
	
	def process_buffer(self):
		while len(self.in_buffer) >= 24:
			response_header = MSRPCRespHeader(self.in_buffer)
			if len(self.in_buffer) >= response_header['frag_len']:
				msg_data = self.in_buffer[:response_header['frag_len']]
				self.in_buffer = self.in_buffer[response_header['frag_len']:]
				yield msg_data
				continue
			break

	async def data_out(self, data):
		if len(data) > self.buffer_size:
			offset = 0
			while True:
				toSend = data[offset:offset+self.buffer_size]
				if not toSend:
					break
				yield toSend
				offset += len(toSend)
		else:
			yield data

	async def data_in(self, data):
		if data is None:
			yield data
		self.in_buffer += data
		for packet in self.process_buffer():
			yield packet
		

class DCERPCTCPTransport:
	def __init__(self, target):
		self.target = target
		self.client = None
		self.connection = None
		self.reader_task = None

		self.packets = asyncio.Queue()
	
	async def disconnect(self):
		try:
			if self.connection is not None:
				await self.connection.close()

			if self.reader_task is not None:
				self.reader_task.cancel()
						
		except Exception as e:
			return None, e

	async def __reader(self):
		try:
			async for data in self.connection.read():
				await self.packets.put(data)
				if data is None or len(data) == 0:
					break
		except asyncio.CancelledError:
			return

	async def send(self, data, forceWriteAndx = 0, forceRecv = 0):
		try:
			await self.connection.write(data)
			return None, None
		except Exception as e:
			return False, e

	async def recv(self, x):
		try:
			data = await self.packets.get()
			return data, None
		except Exception as e:
			return None, e

	async def connect(self):
		packetizer = DCERPCPacketizer()
		client = UniClient(self.target, packetizer)
		self.connection = await client.connect()
		self.reader_task = asyncio.create_task(self.__reader())
