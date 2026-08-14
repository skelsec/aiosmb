
import asyncio
import random

from aiosmb.commons.interfaces.file import SMBFile
from aiosmb.commons.exceptions import SMBException
from aiosmb.wintypes.ntstatus import NTStatus
from aiosmb.dcerpc.v5.rpcrt import MSRPCRespHeader

# A server only offers a limited number of concurrent instances of a given
# named pipe (e.g. \srvsvc). When more opens are attempted at once than there
# are free instances the server refuses the extra ones *immediately* with
# STATUS_PIPE_NOT_AVAILABLE. Instances become free as soon as another client
# closes its handle, so a short bounded retry with jittered back-off lets
# several RPC interfaces share a single SMB connection concurrently.
PIPE_OPEN_MAX_RETRIES = 12
PIPE_OPEN_BASE_DELAY  = 0.1   # seconds
PIPE_OPEN_MAX_DELAY   = 1.0   # seconds (per-attempt cap)


class DCERPCSMBTransport:
	def __init__(self, target):
		self.target = target
		self.smbfile = None
		
		self._max_send_frag = None
		self._recv_buffer = b''

	def get_session_key(self):
		return self.target.smb_connection.get_session_key()
	
	async def connect(self):
		# TODO: if the smb connection is not set up, we need to set it up
		try:
			unc_path = '\\\\%s\\%s%s' % (self.target.smb_connection.target.get_hostname_or_ip(), 'IPC$', self.target.pipe)
			err = None
			for attempt in range(PIPE_OPEN_MAX_RETRIES + 1):
				self.smbfile = SMBFile.from_uncpath(unc_path)
				_, err = await self.smbfile.open(self.target.smb_connection, 'wp')
				if err is None:
					return True, None
				# Only retry the transient "no free pipe instance" condition.
				if not (isinstance(err, SMBException) and err.ntstatus == NTStatus.PIPE_NOT_AVAILABLE):
					return True, err
				if attempt == PIPE_OPEN_MAX_RETRIES:
					break
				# exponential back-off with full jitter to spread out competing opens
				delay = min(PIPE_OPEN_MAX_DELAY, PIPE_OPEN_BASE_DELAY * (2 ** attempt))
				await asyncio.sleep(random.uniform(0, delay))
			return True, err
		except Exception as e:
			return None, e

	async def disconnect(self):
		try:
			await self.smbfile.close()
		except Exception as e:
			return None, e
	
	async def send(self, data, forceWriteAndx = 0, forceRecv = 0):
		try:
			if self._max_send_frag:
				offset = 0
				while 1:
					toSend = data[offset:offset+self._max_send_frag]
					if not toSend:
						break
					total_writen, err = await self.smbfile.write(toSend)
					if err is not None:
						raise err
					offset += len(toSend)
					
			else:
				total_writen, err = await self.smbfile.write(data)
				if err is not None:
					raise err
			
			return True, None
		except Exception as e:
			return None, e

	# old
	#async def recv(self, count): #async def recv(self, forceRecv = 0, count = 0):
	#	try:
	#		#print(count)
	#		data, err = await self.smbfile.read(count)
	#		#print('recv %s' % repr(data))
	#		return data, err
	#	except Exception as e:
	#		return None, e


	# old
	#async def recv(self, count):
	#	try:
	#		hdr_data, err = await self.smbfile.read(24)
	#		if err is not None:
	#			raise err
	#		response_header = MSRPCRespHeader(hdr_data)
	#
	#		msg_data, err = await self.smbfile.read(response_header['frag_len'])
	#		if err is not None:
	#			raise err
	#
	#		return hdr_data+msg_data, None
	#	except Exception as e:
	#		return None, e
		

	async def recv(self, count):
		try:
			if len(self._recv_buffer) >= 24:
				tbuff = self._recv_buffer
				self._recv_buffer = b''
				return tbuff, None

			hdr_data, err = await self.smbfile.read() # this will read MaxReadSize bytes
			if err is not None:
				raise err
			hdr_data += self._recv_buffer
			self._recv_buffer = b''
			response_header = MSRPCRespHeader(hdr_data)

			dlen = len(hdr_data)

			if response_header['frag_len'] == dlen:
				return hdr_data, None
			
			if dlen > response_header['frag_len']:
				self._recv_buffer = hdr_data[response_header['frag_len']:]
				return hdr_data[:response_header['frag_len']], None
			
			body_len = response_header['frag_len'] - len(hdr_data)
			msg_data, err = await self.smbfile.read(body_len)
			if err is not None:
				raise err

			return hdr_data + msg_data, None
		except Exception as e:
			return None, e