import enum
import io
import datetime
import uuid

from aiosmb.utils.ts2dt import *

# https://msdn.microsoft.com/en-us/library/cc246543.aspx
class NegotiateSecurityMode(enum.IntFlag):
	SMB2_NEGOTIATE_SIGNING_ENABLED  = 0x0001
	SMB2_NEGOTIATE_SIGNING_REQUIRED = 0x0002


# https://msdn.microsoft.com/en-us/library/cc246543.aspx
class NegotiateCapabilities(enum.IntFlag):
	SMB2_GLOBAL_CAP_DFS = 0x00000001 #When set, indicates that the client supports the Distributed File System (DFS).
	SMB2_GLOBAL_CAP_LEASING = 0x00000002 #When set, indicates that the client supports leasing.
	SMB2_GLOBAL_CAP_LARGE_MTU = 0x00000004 #When set, indicates that the client supports multi-credit operations.
	SMB2_GLOBAL_CAP_MULTI_CHANNEL = 0x00000008 #When set, indicates that the client supports establishing multiple channels for a single session.
	SMB2_GLOBAL_CAP_PERSISTENT_HANDLES = 0x00000010 #When set, indicates that the client supports persistent handles.
	SMB2_GLOBAL_CAP_DIRECTORY_LEASING = 0x00000020 #When set, indicates that the client supports directory leasing.
	SMB2_GLOBAL_CAP_ENCRYPTION = 0x00000040 #When set, indicates that the client supports encryption.


class NegotiateDialects(enum.Enum):
	SMB202 = 0x0202 #SMB 2.0.2 dialect revision number.
	SMB210 = 0x0210 #SMB 2.1 dialect revision number.<10>
	SMB300 = 0x0300 #SMB 3.0 dialect revision number. <11>
	SMB302 = 0x0302 #SMB 3.0.2 dialect revision number.<12>
	SMB311 = 0x0311 #SMB 3.1.1 dialect revision number.<13>


# https://msdn.microsoft.com/en-us/library/cc246543.aspx
class NEGOTIATE_REQ:
	def __init__(self):
		self.StructureSize   = None
		self.DialectCount    = None
		self.SecurityMode    = None
		self.Reserved        = None
		self.Capabilities    = None
		self.ClientGuid      = None			
		self.ClientStartTime = None
		self.NegotiateContextOffset = None
		self.NegotiateContextCount = None
		self.Reserved2 = None

		self.NegotiateContextList = None
		self.Dialects        = None	

	@staticmethod
	def from_buffer(buff):
		cmd = NEGOTIATE_REQ()
		cmd.StructureSize = int.from_bytes(buff.read(2), byteorder='little', signed = False)
		assert cmd.StructureSize == 36
		cmd.DialectCount = int.from_bytes(buff.read(2), byteorder='little', signed = False)
		assert cmd.DialectCount > 0
		cmd.SecurityMode = NegotiateSecurityMode(int.from_bytes(buff.read(2), byteorder='little', signed = False))
		cmd.Reserved = buff.read(2)
		cmd.Capabilities = NegotiateCapabilities(int.from_bytes(buff.read(4), byteorder='little', signed = False))
		cmd.ClientGuid = uuid.UUID(bytes=buff.read(16))
		# skipping the next field because it's interpretation depends on the data after it...
		pos = buff.tell()
		buff.seek(8, io.SEEK_CUR)
		
		cmd.Dialects = []		
		for i in range(0, cmd.DialectCount):
			cmd.Dialects.append(NegotiateDialects(int.from_bytes(buff.read(2), byteorder = 'little', signed = False)))

		pos_buff_end = buff.tell()
		buff.seek(pos, io.SEEK_SET)

		if NegotiateDialects.SMB311 in cmd.Dialects:
			cmd.NegotiateContextOffset = int.from_bytes(buff.read(4),byteorder = 'little', signed = False)
			cmd.NegotiateContextCount  = int.from_bytes(buff.read(2), byteorder = 'little', signed = False)
			cmd.Reserved2 = int.from_bytes(buff.read(2), byteorder = 'little', signed = False)
			cmd.NegotiateContextList = []
			buff.seek(cmd.NegotiateContextOffset, io.SEEK_SET)

			for i in range(0, cmd.NegotiateContextCount):
				cmd.NegotiateContextList.append(SMB2NegotiateContext.from_buffer(buff))
				pad_pos = buff.tell()
				#aligning buffer, because the next data must be on 8-byte aligned position
				q,m = divmod(pad_pos, 8)
				if m != 0:
					buff.seek((q+1)*8, io.SEEK_SET)
		else:
			cmd.ClientStartTime = wintime2datetime(int.from_bytes(buff.read(8), byteorder = 'little', signed = False))
			buff.seek(pos_buff_end, io.SEEK_SET)

		return cmd

	def __repr__(self):
		t = '==== SMB2 NEGOTIATE REQ ====\r\n'
		t += 'StructureSize: %s\r\n' % self.StructureSize
		t += 'DialectCount:  %s\r\n' % self.DialectCount
		t += 'SecurityMode:  %s\r\n' % self.SecurityMode.name
		t += 'Reserved:      %s\r\n' % self.Reserved
		t += 'Capabilities:  %s\r\n' % repr(self.Capabilities)
		t += 'ClientGuid:    %s\r\n' % self.ClientGuid
		if NegotiateDialects.SMB311 in self.Dialects:
			t += 'NegotiateContextOffset:    %s\r\n' % self.NegotiateContextOffset
			t += 'NegotiateContextCount:    %s\r\n' % self.NegotiateContextCount
			t += 'Reserved2:    %s\r\n' % self.Reserved2
			for ctx in self.NegotiateContextList:
				t += repr(ctx)
		else:
			t += 'ClientStartTime:    %s\r\n' % self.ClientStartTime
		
		for dialect in self.Dialects:
			t += '\t Dialect: %s\r\n' % dialect.name

		return t


class SMB2ContextType(enum.Enum):
	SMB2_PREAUTH_INTEGRITY_CAPABILITIES = 0x0001
	SMB2_ENCRYPTION_CAPABILITIES = 0x0002


class SMB2HashAlgorithm(enum.Enum):
	SHA_512 = 0x0001


# https://msdn.microsoft.com/en-us/library/mt208834.aspx
class SMB2NegotiateContext:
	def __init__(self):
		self.ContextType = None
		self.DataLength  = None
		self.Reserved    = None
		self.Data        = None

	@staticmethod
	def from_buffer(buff):
		ctx = SMB2NegotiateContext()
		ctx.ContextType = SMB2ContextType(int.from_bytes(buff.read(2), byteorder = 'little', signed = False))
		ctx.DataLength  = int.from_bytes(buff.read(2), byteorder = 'little', signed = False)
		ctx.Reserved    = buff.read(4)

		if ctx.ContextType == SMB2ContextType.SMB2_PREAUTH_INTEGRITY_CAPABILITIES:
			ctx.Data = SMB2PreauthIntegrityCapabilities.from_buffer(buff)

		elif ctx.ContextType == SMB2ContextType.SMB2_ENCRYPTION_CAPABILITIES:
			ctx.Data = SMB2EncryptionCapabilities.from_buffer(buff)

		return ctx

	def to_bytes(self):
		t  = self.ContextType.to_bytes(2, byteorder = 'little', signed=False)
		t += self.DataLength.to_bytes(2, byteorder = 'little', signed=False)
		t += self.Reserved.to_bytes(4, byteorder = 'little', signed=False)

		return t

	def __repr__(self):
		t = '==== SMB2 Negotiate Context ====\r\n'
		t += 'ConextType: %s\r\n' % self.ContextType.name
		t += 'DataLength: %s\r\n' % self.DataLength
		t += 'Data: %s\r\n' % repr(self.Data)

		return t


class SMB2PreauthIntegrityCapabilities:
	def __init__(self, data=None):
		self.HashAlgorithmCount = None
		self.SaltLength         = None
		self.HashAlgorithms     = None
		self.Salt               = None

	@staticmethod
	def from_buffer(buff):
		cap = SMB2PreauthIntegrityCapabilities()
		cap.HashAlgorithmCount = int.from_bytes(buff.read(2), byteorder='little', signed = False)
		cap.SaltLength = int.from_bytes(buff.read(2), byteorder = 'little', signed = False)
		cap.HashAlgorithms = []
		for i in range(cap.HashAlgorithmCount):
			cap.HashAlgorithms.append(SMB2HashAlgorithm(int.from_bytes(buff.read(2), byteorder ='little', signed = False)))

		cap.Salt = buff.read(cap.SaltLength)

		return cap

	def to_bytes(self):
		t  = self.HashAlgorithmCount.to_bytes(2, byteorder = 'little', signed=False)
		t += self.SaltLength.to_bytes(2, byteorder = 'little', signed=False)
		for hashalgo in self.HashAlgorithms:
			t += hashalgo.to_bytes(2, byteorder = 'little', signed=False)
		
		t += self.Salt

		return t

	def __repr__(self):
		t = '==== SMB2 Preauth Integrity Capabilities ====\r\n'
		t += 'HashAlgorithmCount: %s\r\n' % self.HashAlgorithmCount
		t += 'SaltLength: %s\r\n' % self.SaltLength
		t += 'Salt: %s\r\n' % self.Salt
		
		for algo in self.HashAlgorithms:
			t += 'HashAlgo: %s\r\n' % algo.name

		return t


class SMB2Cipher(enum.Enum):
	AES_128_CCM = 0x0001
	AES_128_GCM = 0x0002


class SMB2EncryptionCapabilities:
	def __init__(self):
		self.CipherCount = None
		self.Ciphers = None

	@staticmethod
	def from_buffer(buff):
		cap = SMB2EncryptionCapabilities()
		cap.CipherCount = int.from_bytes(buff.read(2), byteorder='little', signed = False)
		cap.Ciphers = []

		for i in range(cap.CipherCount):
			cap.Ciphers.append(SMB2Cipher(int.from_bytes(buff.read(2), byteorder='little', signed = False)))

		return cap

	def to_bytes(self):
		t  = self.CipherCount.to_bytes(2, byteorder = 'little', signed=False)
		for cipher in self.Ciphers:
			t += cipher.to_bytes(2, byteorder = 'little', signed=False)

		return t
			

	def __repr__(self):
		t = '==== SMB2 Encryption Capabilities ====\r\n'
		t += 'CipherCount: %s\r\n' % self.CipherCount
		for cipher in self.Ciphers:
			t += 'Cipher: %s\r\n' % cipher.name

		return t


# https://msdn.microsoft.com/en-us/library/cc246561.aspx
class NEGOTIATE_REPLY:
	def __init__(self):
		self.StructureSize = None
		self.SecurityMode = None
		self.DialectRevision = None
		self.NegotiateContextCount = None # or reserved
		self.ServerGuid = None
		self.Capabilities = None
		self.MaxTransactSize = None
		self.MaxReadSize = None
		self.MaxWriteSize = None
		self.SystemTime = None
		self.ServerStartTime = None
		self.SecurityBufferOffset = None
		self.SecurityBufferLength = None
		self.NegotiateContextOffset = None
		self.Buffer = None
		self.Padding = None
		self.NegotiateContextList = None
		self.ppos = 64

	@staticmethod
	def from_bytes(bbuff):
		return NEGOTIATE_REPLY.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		msg = NEGOTIATE_REPLY()
		msg.StructureSize   = int.from_bytes(buff.read(2), byteorder='little', signed = False)
		assert msg.StructureSize == 65
		msg.SecurityMode    = NegotiateSecurityMode(int.from_bytes(buff.read(2), byteorder='little', signed = False))
		msg.DialectRevision = NegotiateDialects(int.from_bytes(buff.read(2), byteorder='little', signed = False))
		msg.NegotiateContextCount  = int.from_bytes(buff.read(2), byteorder='little', signed = False)
		msg.ServerGuid      = uuid.UUID(bytes_le=buff.read(16))
		msg.Capabilities    = NegotiateCapabilities(int.from_bytes(buff.read(4), byteorder='little', signed = False))
		msg.MaxTransactSize = int.from_bytes(buff.read(4), byteorder='little', signed = False)
		msg.MaxReadSize     = int.from_bytes(buff.read(4), byteorder='little', signed = False)
		msg.MaxWriteSize    = int.from_bytes(buff.read(4), byteorder='little', signed = False)
		msg.SystemTime      = timestamp2datetime(buff.read(8))
		msg.ServerStartTime = timestamp2datetime(buff.read(8))
		msg.SecurityBufferOffset = int.from_bytes(buff.read(2), byteorder='little', signed = False)
		msg.SecurityBufferLength = int.from_bytes(buff.read(2), byteorder='little', signed = False)
		msg.NegotiateContextOffset = int.from_bytes(buff.read(4), byteorder='little', signed = False)

		pos = buff.tell()
		if msg.SecurityBufferLength != 0:
			buff.seek(msg.SecurityBufferOffset, io.SEEK_SET)
			msg.Buffer = buff.read(msg.SecurityBufferLength)

		pos_buff_end = buff.tell()

		if msg.DialectRevision == NegotiateDialects.SMB311:
			msg.NegotiateContextList = []
			buff.seek(msg.NegotiateContextOffset, io.SEEK_SET)
			for i in range(msg.NegotiateContextCount):
				msg.NegotiateContextList.append(SMB2NegotiateContext.from_buffer(buff))

		return msg

	@staticmethod
	def construct(data, SecurityMode, DialectRevision, ServerGuid, Capabilities, 
					MaxTransactSize= 8388608, MaxReadSize= 8388608, MaxWriteSize= 8388608, 
					SystemTime = datetime.datetime.now(), 
					ServerStartTime=datetime.datetime.now() - datetime.timedelta(days=1),
					NegotiateContextList = [], ppos = None):
		
		cmd = NEGOTIATE_REPLY()
		if ppos is None:
			ppos = cmd.ppos
		#ppos = the size of the message until this class. it is needed to calculate the offsets!
		cmd.StructureSize = 65
		cmd.SecurityMode = SecurityMode
		cmd.DialectRevision = DialectRevision
		cmd.NegotiateContextCount = len(NegotiateContextList) #or reserved
		cmd.ServerGuid = ServerGuid
		cmd.Capabilities = Capabilities
		cmd.MaxTransactSize = MaxTransactSize
		cmd.MaxReadSize = MaxReadSize
		cmd.MaxWriteSize = MaxWriteSize
		cmd.SystemTime = SystemTime
		cmd.ServerStartTime = ServerStartTime
		cmd.SecurityBufferOffset = ppos + 64
		cmd.SecurityBufferLength = len(data)
		if NegotiateContextList == []:
			cmd.NegotiateContextOffset = 0
		else:
			cmd.NegotiateContextOffset = cmd.SecurityBufferOffset + cmd.SecurityBufferLength ##WARNING! THIS SHOULD BE PADDED!!!!!
		cmd.Buffer = data
		cmd.NegotiateContextList = NegotiateContextList

		return cmd

	def to_bytes(self, ppos = None):
		if ppos is None:
			ppos = self.ppos
		t  = self.StructureSize.to_bytes(2, byteorder = 'little', signed=False)
		t += self.SecurityMode.to_bytes(2, byteorder = 'little', signed=False)
		t += self.DialectRevision.value.to_bytes(2, byteorder = 'little', signed=False)
		t += self.NegotiateContextCount.to_bytes(2, byteorder = 'little', signed=False)
		t += self.ServerGuid.bytes_le
		t += self.Capabilities.to_bytes(4, byteorder = 'little', signed=False)
		t += self.MaxTransactSize.to_bytes(4, byteorder = 'little', signed=False)
		t += self.MaxReadSize.to_bytes(4, byteorder = 'little', signed=False)
		t += self.MaxWriteSize.to_bytes(4, byteorder = 'little', signed=False)
		t += dt2wt(self.SystemTime).to_bytes(8, byteorder = 'little', signed=False)
		t += dt2wt(self.ServerStartTime).to_bytes(8, byteorder = 'little', signed=False)

		t += self.SecurityBufferOffset.to_bytes(2, byteorder = 'little', signed=False)
		t += self.SecurityBufferLength.to_bytes(2, byteorder = 'little', signed=False)
		print(self.NegotiateContextOffset)
		t += self.NegotiateContextOffset.to_bytes(4, byteorder = 'little', signed=False)
		t += self.Buffer

		if self.NegotiateContextCount > 0:
			for ngctx in self.NegotiateContextList:
				t+= ngctx.to_bytes()
				#PADDING!
				q,m = divmod(len(t)+ppos,8)
				t+= b'\x00'*( (q+1)*8 -  len(t)   )

		return t

	def __repr__(self):
		t = '==== SMB2 NEGOTIATE REPLY ====\r\n'
		t += 'StructureSize: %s\r\n' % self.StructureSize
		t += 'SecurityMode: %s\r\n' % repr(self.SecurityMode)
		t += 'DialectRevision: %s\r\n' % self.DialectRevision.name
		t += 'ServerGuid: %s\r\n' % self.ServerGuid
		t += 'Capabilities: %s\r\n' % repr(self.Capabilities)
		t += 'MaxTransactSize: %s\r\n' % self.MaxTransactSize
		t += 'MaxReadSize: %s\r\n' % self.MaxReadSize
		t += 'MaxWriteSize: %s\r\n' % self.MaxWriteSize
		t += 'SystemTime: %s\r\n' % self.SystemTime.isoformat()
		t += 'ServerStartTime: %s\r\n' % self.ServerStartTime.isoformat()
		t += 'SecurityBufferOffset: %s\r\n' % self.SecurityBufferOffset
		t += 'SecurityBufferLength: %s\r\n' % self.SecurityBufferLength
		t += 'Buffer: %s\r\n' % self.Buffer
		t += 'NegotiateContextList: %s\r\n' % self.NegotiateContextList
		return t
