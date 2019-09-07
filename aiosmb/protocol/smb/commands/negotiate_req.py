import io

# https://msdn.microsoft.com/en-us/library/ee441913.aspx
class SMB_COM_NEGOTIATE_REQ:
	def __init__(self):
		##### parameters ####
		self.WordCount = 0
		##### SMB_Data ###
		self.ByteCount = None
		self.Dialects  = [] #list fo dialect strings

	@staticmethod
	def from_bytes(bbuff):
		return SMB_COM_NEGOTIATE_REQ.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		cmd = SMB_COM_NEGOTIATE_REQ()
		cmd.WordCount = int.from_bytes(buff.read(1), byteorder='little', signed = False)
		cmd.ByteCount = int.from_bytes(buff.read(2), byteorder='little', signed = False)
		dialect_buffer = buff.read(cmd.ByteCount)
		#print(dialect_buffer)
		
		i = 0
		while i < len(dialect_buffer):
			if not dialect_buffer[i] == 2:
				#print(i)
				raise Exception('Dialect buffer expected byte 0x02!')
			m = dialect_buffer[i:].find(b'\x00')
			if m == -1:
				raise Exception('Could not find end of string!')
			cmd.Dialects.append(dialect_buffer[i+1: m+i].decode('ascii'))
			i += m+1
		return cmd
		
		
	def to_bytes(self):
		t = self.WordCount.to_bytes(1, byteorder='little', signed = False)
		
		dialect_buffer = b''
		for dialect in self.Dialects:
			dialect_buffer += b'\x02' + dialect.encode('ascii') + b'\x00'
			
		t+= len(dialect_buffer).to_bytes(2, byteorder='little', signed = False)
		t+= dialect_buffer
		
		return t

	def __repr__(self):
		t = '===SMB_COM_NEGOTIATE_REQ===\r\n'
		return t
		
def test():
	data = bytes.fromhex('002200024e54204c4d20302e31320002534d4220322e3030320002534d4220322e3f3f3f00')
	nego = SMB_COM_NEGOTIATE_REQ.from_bytes(data)
	print(nego.Dialects)
	if 'NT LM 0.12' not in nego.Dialects:
		raise Exception('Error!')
	if 'SMB 2.002' not in nego.Dialects:
		raise Exception('Error!')
	if 'SMB 2.???' not in nego.Dialects:
		raise Exception('Error!')
		
	data_reconstructed = nego.to_bytes()
	assert data == data_reconstructed
		
if __name__ == '__main__':
	test()