
from aiosmb.commons.interfaces.file import SMBFile
from aiosmb.commons.utils.decorators import red, rr

#currently only capable of using an already established SMB connection!!!
# 

class DCERPCSMBTransport:
	def __init__(self, target):
		self.target = target
		self.smbfile = None
		
		self._max_send_frag = None
	
	@red
	async def connect(self):
		# TODO: if the smb connection is not set up, we need to set it up

		unc_path = '\\\\%s\\%s%s' % (self.target.smb_connection.target.get_hostname_or_ip(), 'IPC$', self.target.pipe)
		self.smbfile = SMBFile.from_uncpath(unc_path)
		await self.smbfile.open(self.target.smb_connection, 'wp')
		return True, None

	@red
	async def disconnect(self):
		await self.smbfile.close()
	
	@red
	async def send(self, data, forceWriteAndx = 0, forceRecv = 0):
		if self._max_send_frag:
			offset = 0
			while 1:
				toSend = data[offset:offset+self._max_send_frag]
				if not toSend:
					break
				await self.smbfile.write(toSend)
				offset += len(toSend)
				
		else:
			await self.smbfile.write(data)
		
		return True, None

	
	@red
	async def recv(self, count): #async def recv(self, forceRecv = 0, count = 0):
		#print(count)
		data = await self.smbfile.read(count)
		#print('recv %s' % repr(data))
		return data, None