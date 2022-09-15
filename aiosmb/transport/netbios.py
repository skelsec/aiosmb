
from asysocks.unicomm.common.packetizers import Packetizer

class NetBIOSPacketizer(Packetizer):
	def __init__(self, buffer_size = 65535):
		Packetizer.__init__(self, buffer_size)
		self.in_buffer = b''
		self.__total_size = -1
	
	def process_buffer(self):
		if self.__total_size == -1:
			if len(self.in_buffer) > 5:
				self.__total_size = int.from_bytes(self.in_buffer[1:4], byteorder='big', signed = False) + 4

		while self.__total_size > -1 and len(self.in_buffer) >= self.__total_size:
			if self.__total_size > -1 and len(self.in_buffer) >= self.__total_size:
				msg_data = self.in_buffer[:self.__total_size][4:]
				self.in_buffer = self.in_buffer[self.__total_size:]
				self.__total_size = -1
				if len(self.in_buffer) > 5:
					self.__total_size = int.from_bytes(self.in_buffer[1:4], byteorder='big', signed = False) + 4
						
				#print('%s nbmsg! ' % (self.network_transport.writer.get_extra_info('peername')[0], ))
				#print('[NetBIOS] MSG dispatched')
				yield msg_data

	async def data_out(self, smb_msg_data):
		if smb_msg_data is None:
			return
		data  = b'\x00'
		data += len(smb_msg_data).to_bytes(3, byteorder='big', signed = False)
		data += smb_msg_data
		yield data

	async def data_in(self, data):
		if data is None:
			for packet in self.process_buffer():
				yield packet
		else:
			self.in_buffer += data
			for packet in self.process_buffer():
				yield packet

		#if data is None:
		#	yield data
		#self.in_buffer += data
		#for packet in self.process_buffer():
		#	yield packet
		
		
