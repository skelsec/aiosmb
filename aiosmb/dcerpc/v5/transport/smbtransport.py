from aiosmb.filereader import SMBFileReader
from aiosmb.dcerpc.v5.transport.common import *

class SMBTransport(DCERPCTransport):
	def __init__(self, connection, filename):
		self.transport_type = 'SMB'
		self.target = connection.target
		self.filename = filename
		self.connection = connection
		self.pipe_reader = SMBFileReader(connection)
		
		self._max_send_frag =  None
		
	async def connect(self):
		filename = '\\\\%s\\%s%s' % (self.target.get_ip(), 'IPC$', self.filename)
		await self.pipe_reader.open(filename, 'wp')
	
	async def disconnect(self):
		try:
			await self.pipe_reader.close()
		except:
			pass
		
	async def send(self, data, forceWriteAndx = 0, forceRecv = 0):
		if self._max_send_frag:
			offset = 0
			while 1:
				toSend = data[offset:offset+self._max_send_frag]
				if not toSend:
					break
				await self.pipe_reader.write(toSend, offset = offset)
				offset += len(toSend)
				
		else:
			await self.pipe_reader.write(data)
	
	async def recv(self, forceRecv = 0, count = 0):
		t = await self.pipe_reader.read(-1)
		return t