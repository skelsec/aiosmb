import io
from aiosmb.protocol.smb.commons import SMBSecurityMode

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
		


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/a4229e1a-8a4e-489a-a2eb-11b7f360e60c
class SMB_COM_NEGOTIATE_REPLY:
	def __init__(self):
		##### parameters ####
		self.WordCount = 0
		self.DialectIndex = None
		self.SecurityMode = None
		self.MaxMpxCount = None
		self.MaxNumberVcs = None
		self.MaxBufferSize = None
		self.MaxRawSize = None
		self.SessionKey = None
		self.Capabilities = None
		self.SystemTime = None
		self.ServerTimeZone = None
		self.ChallengeLength = None
		##### SMB_Data ###
		self.ByteCount = None
		self.Challenge = None
		self.DomainName = None

	@staticmethod
	def from_bytes(bbuff):
		return SMB_COM_NEGOTIATE_REPLY.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		cmd = SMB_COM_NEGOTIATE_REPLY()
		cmd.WordCount = int.from_bytes(buff.read(1), byteorder='little', signed = False) # 0x11
		cmd.DialectIndex = int.from_bytes(buff.read(2), byteorder='little', signed = False)
		cmd.SecurityMode = SMBSecurityMode(int.from_bytes(buff.read(1), byteorder='little', signed = False))
		cmd.MaxMpxCount = int.from_bytes(buff.read(2), byteorder='little', signed = False)
		cmd.MaxNumberVcs = int.from_bytes(buff.read(2), byteorder='little', signed = False)
		cmd.MaxBufferSize = int.from_bytes(buff.read(4), byteorder='little', signed = False)
		cmd.MaxRawSize = int.from_bytes(buff.read(4), byteorder='little', signed = False)
		cmd.SessionKey = buff.read(4)
		cmd.Capabilities = int.from_bytes(buff.read(4), byteorder='little', signed = False)
		cmd.SystemTime = buff.read(8)
		cmd.ServerTimeZone = int.from_bytes(buff.read(2), byteorder='little', signed = False)
		cmd.ChallengeLength = int.from_bytes(buff.read(1), byteorder='little', signed = False)
		
		
		cmd.ByteCount = int.from_bytes(buff.read(2), byteorder='little', signed = False)

		cmd.Challenge = buff.read(cmd.ChallengeLength)
		cmd.DomainName = buff.read(cmd.ByteCount - cmd.ChallengeLength)
		
		return cmd

	def __repr__(self):
		t = '===SMB_COM_NEGOTIATE_REPLY===\r\n'
		for x in self.__dict__:
			t += '%s : %s \n' % (x, self.__dict__[x])
		return t