import enum
import io
import datetime
import uuid

from aiosmb.commons.utils.ts2dt import *
from aiosmb.protocol.common import NegotiateDialects
from aiosmb.wintypes.dtyp.constrcuted_security.guid import *


# https://msdn.microsoft.com/en-us/library/cc246543.aspx
class NegotiateSecurityMode(enum.IntFlag):
	SMB2_NEGOTIATE_SIGNING_ENABLED  = 0x0001
	SMB2_NEGOTIATE_SIGNING_REQUIRED = 0x0002


# https://msdn.microsoft.com/en-us/library/cc246543.aspx
class NegotiateCapabilities(enum.IntFlag):
	DFS = 0x00000001 #When set, indicates that the client supports the Distributed File System (DFS).
	LEASING = 0x00000002 #When set, indicates that the client supports leasing.
	LARGE_MTU = 0x00000004 #When set, indicates that the client supports multi-credit operations.
	MULTI_CHANNEL = 0x00000008 #When set, indicates that the client supports establishing multiple channels for a single session.
	PERSISTENT_HANDLES = 0x00000010 #When set, indicates that the client supports persistent handles.
	DIRECTORY_LEASING = 0x00000020 #When set, indicates that the client supports directory leasing.
	ENCRYPTION = 0x00000040 #When set, indicates that the client supports encryption.


# https://msdn.microsoft.com/en-us/library/cc246543.aspx
class NEGOTIATE_REQ:
	def __init__(self):
		self.StructureSize   = 36
		self.DialectCount    = None
		self.SecurityMode    = None
		self.Reserved        = 0
		self.Capabilities    = None
		self.ClientGuid      = None			
		self.ClientStartTime = 0
		self.NegotiateContextOffset = None
		self.NegotiateContextCount = None
		self.Reserved2 = 0

		self.NegotiateContextList = []
		self.Dialects        = []
		
	def to_bytes(self):
		if self.Dialects == []:
			raise Exception('At least one dialect MUST be set!')

		t = self.StructureSize.to_bytes(2, byteorder='little', signed = False)
		t += len(self.Dialects).to_bytes(2, byteorder='little', signed = False)
		t += self.SecurityMode.to_bytes(2, byteorder='little', signed = False)
		t += self.Reserved.to_bytes(2, byteorder='little', signed = False)
		t += self.Capabilities.to_bytes(4, byteorder='little', signed = False)
		t += self.ClientGuid.to_bytes()
		if NegotiateDialects.SMB311 in self.Dialects:
			dp = b''
			for dialect in self.Dialects:
				dp += dialect.value.to_bytes(2, byteorder='little', signed = False)
			
			padding_starts = 64+2+2+2+2+4+16+8+len(dp)
			dp += b'\x00' * ((8 - padding_starts) % 8)
			self.NegotiateContextOffset = 64+2+2+2+2+4+16+8+len(dp)
			self.NegotiateContextCount = len(self.NegotiateContextList)
			t += self.NegotiateContextOffset.to_bytes(4, byteorder='little', signed = False)
			t += self.NegotiateContextCount.to_bytes(2, byteorder='little', signed = False)
			t += self.Reserved2.to_bytes(2, byteorder='little', signed = False)
			t += dp

			for ctx in self.NegotiateContextList:
				t += ctx.to_bytes()
				t += b'\x00' * ((8 - len(t)) % 8)
			
		else:
			t += self.ClientStartTime.to_bytes(8, byteorder='little', signed = False)
			
			for dialect in self.Dialects:
				t += dialect.value.to_bytes(2, byteorder='little', signed = False)
		
		return t

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
		cmd.ClientGuid = GUID.from_buffer(buff)
		# skipping the next field because it's interpretation depends on the data after it...
		pos = buff.tell()
		buff.seek(8, io.SEEK_CUR)
		
		cmd.Dialects = []		
		for _ in range(0, cmd.DialectCount):
			cmd.Dialects.append(NegotiateDialects(int.from_bytes(buff.read(2), byteorder = 'little', signed = False)))

		pos_buff_end = buff.tell()
		buff.seek(pos, io.SEEK_SET)

		if NegotiateDialects.SMB311 in cmd.Dialects:
			cmd.NegotiateContextOffset = int.from_bytes(buff.read(4),byteorder = 'little', signed = False)
			cmd.NegotiateContextCount  = int.from_bytes(buff.read(2), byteorder = 'little', signed = False)
			cmd.Reserved2 = int.from_bytes(buff.read(2), byteorder = 'little', signed = False)
			cmd.NegotiateContextList = []
			buff.seek(cmd.NegotiateContextOffset, io.SEEK_SET)

			for _ in range(0, cmd.NegotiateContextCount):
				cmd.NegotiateContextList.append(SMB2NegotiateContext.from_buffer(buff))
				pad_pos = buff.tell()
				#aligning buffer, because the next data must be on 8-byte aligned position
				q,m = divmod(pad_pos, 8)
				if m != 0:
					buff.seek((q+1)*8, io.SEEK_SET)
		else:
			cmd.ClientStartTime = int.from_bytes(buff.read(8), byteorder = 'little', signed = False)
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
	PREAUTH_INTEGRITY_CAPABILITIES = 0x0001
	ENCRYPTION_CAPABILITIES = 0x0002
	COMPRESSION_CAPABILITIES = 0x0003 #The Data field contains a list of compression algorithms, as specified in section 2.2.3.1.3<13>.
	NETNAME_NEGOTIATE_CONTEXT_ID = 0x0005 #The Data field contains the server name to which the client connects<14>.


class SMB2HashAlgorithm(enum.Enum):
	SHA_512 = 0x0001

#
# https://msdn.microsoft.com/en-us/library/mt208834.aspx
class SMB2NegotiateContext:
	def __init__(self):
		pass

	@staticmethod
	def from_buffer(buff):
		pos = buff.tell()
		ContextType = SMB2ContextType(int.from_bytes(buff.read(2), byteorder = 'little', signed = False))
		buff.seek(pos)

		if ContextType == SMB2ContextType.PREAUTH_INTEGRITY_CAPABILITIES:
			return SMB2PreauthIntegrityCapabilities.from_buffer(buff)

		elif ContextType == SMB2ContextType.ENCRYPTION_CAPABILITIES:
			return SMB2EncryptionCapabilities.from_buffer(buff)

		elif ContextType == SMB2ContextType.COMPRESSION_CAPABILITIES:
			return SMB2CompressionCapabilities.from_buffer(buff)

		elif ContextType == SMB2ContextType.PREAUTH_INTEGRITY_CAPABILITIES:
			return SMB2NetnameNegotiateContextID.from_buffer(buff)

		else:
			raise Exception('Unknown contextype %s' % ContextType)

class SMB2PreauthIntegrityCapabilities:
	def __init__(self):
		self.ContextType = SMB2ContextType.PREAUTH_INTEGRITY_CAPABILITIES
		self.DataLength  = None
		self.Reserved    = 0

		self.HashAlgorithmCount = None
		self.SaltLength         = None
		self.HashAlgorithms     = None
		self.Salt               = None

	@staticmethod
	def from_buffer(buff):
		cap = SMB2PreauthIntegrityCapabilities()
		cap.ContextType = SMB2ContextType(int.from_bytes(buff.read(2), byteorder = 'little', signed = False))
		cap.DataLength  = int.from_bytes(buff.read(2), byteorder = 'little', signed = False)
		cap.Reserved    = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		cap.HashAlgorithmCount = int.from_bytes(buff.read(2), byteorder='little', signed = False)
		cap.SaltLength = int.from_bytes(buff.read(2), byteorder = 'little', signed = False)
		cap.HashAlgorithms = []
		for _ in range(cap.HashAlgorithmCount):
			cap.HashAlgorithms.append(SMB2HashAlgorithm(int.from_bytes(buff.read(2), byteorder ='little', signed = False)))

		cap.Salt = buff.read(cap.SaltLength)

		return cap

	@staticmethod
	def construct(hash_algos = [SMB2HashAlgorithm.SHA_512], salt = b''):
		cap = SMB2PreauthIntegrityCapabilities()
		cap.HashAlgorithms = hash_algos
		cap.Salt = salt
		return cap

	def to_bytes(self):
		self.SaltLength = len(self.Salt)
		self.HashAlgorithmCount = len(self.HashAlgorithms)
		data = self.HashAlgorithmCount.to_bytes(2, byteorder = 'little', signed=False)
		data += self.SaltLength.to_bytes(2, byteorder = 'little', signed=False)
		for hashalgo in self.HashAlgorithms:
			data += hashalgo.value.to_bytes(2, byteorder = 'little', signed=False)
		data += self.Salt

		self.DataLength = len(data)

		t = self.ContextType.value.to_bytes(2, byteorder = 'little', signed=False)
		t += self.DataLength.to_bytes(2, byteorder = 'little', signed=False)
		t += self.Reserved.to_bytes(4, byteorder = 'little', signed=False)
		t += data
		
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
		self.ContextType = SMB2ContextType.ENCRYPTION_CAPABILITIES
		self.DataLength  = None
		self.Reserved    = 0

		self.CipherCount = None
		self.Ciphers = None

	@staticmethod
	def from_buffer(buff):
		cap = SMB2EncryptionCapabilities()
		cap.ContextType = SMB2ContextType(int.from_bytes(buff.read(2), byteorder = 'little', signed = False))
		cap.DataLength  = int.from_bytes(buff.read(2), byteorder = 'little', signed = False)
		cap.Reserved    = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		cap.CipherCount = int.from_bytes(buff.read(2), byteorder='little', signed = False)
		cap.Ciphers = []

		for _ in range(cap.CipherCount):
			cap.Ciphers.append(SMB2Cipher(int.from_bytes(buff.read(2), byteorder='little', signed = False)))

		return cap

	@staticmethod
	def from_enc_list(supp_enc_list):
		#supp_enc_list > a list of SMB2Cipher enums
		s = SMB2EncryptionCapabilities()
		s.Ciphers = supp_enc_list
		s.CipherCount = len(supp_enc_list)
		return s

	def to_bytes(self):
		data  = self.CipherCount.to_bytes(2, byteorder = 'little', signed=False)
		for cipher in self.Ciphers:
			data += cipher.value.to_bytes(2, byteorder = 'little', signed=False)

		self.DataLength = len(data)
		t = self.ContextType.value.to_bytes(2, byteorder = 'little', signed=False)
		t += self.DataLength.to_bytes(2, byteorder = 'little', signed=False)
		t += self.Reserved.to_bytes(4, byteorder = 'little', signed=False)
		t += data


		return t
			

	def __repr__(self):
		t = '==== SMB2 Encryption Capabilities ====\r\n'
		t += 'CipherCount: %s\r\n' % self.CipherCount
		for cipher in self.Ciphers:
			t += 'Cipher: %s\r\n' % cipher.name

		return t

class SMB2CompressionType(enum.Enum):
	NONE = 0x0000 #No compression
	LZNT1 = 0x0001 #LZNT1 compression algorithm
	LZ77 = 0x0002 #LZ77 compression algorithm
	LZ77_Huffman = 0x0003 #LZ77+Huffman compression algorithm
	Pattern_V1 = 0x0004 #Pattern Scanning algorithm

class SMB2CompressionFlags(enum.Enum):
	NONE = 0x00000000 #Chained compression is not supported.
	CHAINED = 0x00000001 #Chained compression is supported on this connection.

class SMB2CompressionCapabilities:
	def __init__(self):
		self.ContextType = SMB2ContextType.COMPRESSION_CAPABILITIES
		self.DataLength  = None
		self.Reserved    = 0

		self.CompressionAlgorithmCount = None
		self.Padding = 0
		self.Flags = None
		self.CompressionAlgorithms = []

	@staticmethod
	def from_buffer(buff):
		cap = SMB2CompressionCapabilities()
		cap.ContextType = SMB2ContextType(int.from_bytes(buff.read(2), byteorder = 'little', signed = False))
		cap.DataLength  = int.from_bytes(buff.read(2), byteorder = 'little', signed = False)
		cap.Reserved    = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		cap.CompressionAlgorithmCount = int.from_bytes(buff.read(2), byteorder='little', signed = False)
		cap.Padding = int.from_bytes(buff.read(2), byteorder='little', signed = False)
		cap.Flags = SMB2CompressionFlags(int.from_bytes(buff.read(4), byteorder='little', signed = False))

		for _ in range(cap.CompressionAlgorithmCount):
			cap.CompressionAlgorithms.append(SMB2CompressionType(int.from_bytes(buff.read(2), byteorder='little', signed = False)))

		return cap

	@staticmethod
	def from_comp_list(supp_comp_list, is_chained = False):
		#supp_comp_list > a list of SMB2CompressionType enums
		# flags > bool, will be converted to SMB2CompressionFlags 
		s = SMB2CompressionCapabilities()
		s.Flags = SMB2CompressionFlags.NONE
		if is_chained is True:
			s.Flags = SMB2CompressionFlags.CHAINED
		s.CompressionAlgorithms = supp_comp_list
		s.CompressionAlgorithmCount = len(supp_comp_list)
		return s

	def to_bytes(self):
		
		data  = self.CompressionAlgorithmCount.to_bytes(2, byteorder = 'little', signed=False)
		data += self.Padding.to_bytes(2, byteorder = 'little', signed=False)
		data += self.Flags.value.to_bytes(2, byteorder = 'little', signed=False)
		data += self.CompressionAlgorithmCount.to_bytes(2, byteorder = 'little', signed=False)
		for compalgo in self.CompressionAlgorithms:
			data += compalgo.value.to_bytes(2, byteorder = 'little', signed=False)
		
		self.DataLength = len(data)
		t = self.ContextType.value.to_bytes(2, byteorder = 'little', signed=False)
		t += self.DataLength.to_bytes(2, byteorder = 'little', signed=False)
		t += self.Reserved.to_bytes(4, byteorder = 'little', signed=False)
		t += data

		return t
			

	def __repr__(self):
		t = '==== SMB2 Compression Capabilities ====\r\n'
		t += 'Flags: %s\r\n' % self.Flags.name
		for compalgo in self.CompressionAlgorithms:
			t += 'Compression type: %s\r\n' % compalgo.name

		return t

class SMB2NetnameNegotiateContextID:
	def __init__(self):
		self.ContextType = SMB2ContextType.NETNAME_NEGOTIATE_CONTEXT_ID
		self.DataLength  = None
		self.Reserved    = None

		self.NetName = None

	@staticmethod
	def from_buffer(buff):
		#raise Exception('Documentation doesnt specify the size')
		cap = SMB2NetnameNegotiateContextID()
		cap.ContextType = SMB2ContextType(int.from_bytes(buff.read(2), byteorder = 'little', signed = False))
		cap.DataLength  = int.from_bytes(buff.read(2), byteorder = 'little', signed = False)
		cap.Reserved    = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		cap.NetName     = buff.read(cap.DataLength).decode('utf-16-le')
		return cap

	def to_bytes(self):
		return self.NetName.encode('utf-18-le')
			
	def __repr__(self):
		t = '==== SMB2 Netname Negotiate Context ID ====\r\n'
		t += 'NetName: %s\r\n' % self.NetName
		return t

# https://msdn.microsoft.com/en-us/library/cc246561.aspx
class NEGOTIATE_REPLY:
	def __init__(self):
		self.StructureSize = 65
		self.SecurityMode = None
		self.DialectRevision = None
		self.NegotiateContextCount = None # or reserved
		self.ServerGuid = None
		self.Capabilities = None
		self.MaxTransactSize = 8388608
		self.MaxReadSize = 8388608
		self.MaxWriteSize = 8388608
		self.SystemTime = None
		self.ServerStartTime = None
		self.SecurityBufferOffset = 0
		self.SecurityBufferLength = 0
		self.NegotiateContextOffset = 0
		self.Buffer = b''
		self.Padding = None
		self.NegotiateContextList = []

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
		msg.ServerGuid      = GUID.from_bytes(buff.read(16))
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
			for _ in range(msg.NegotiateContextCount):
				msg.NegotiateContextList.append(SMB2NegotiateContext.from_buffer(buff))
				padsize = ((8 - buff.tell()) % 8)
				buff.seek(padsize, io.SEEK_CUR)

		return msg

	def to_bytes(self):
		self.SecurityBufferOffset = 0x80
		self.SecurityBufferLength = len(self.Buffer)

		t  = self.StructureSize.to_bytes(2, byteorder = 'little', signed=False)
		t += self.SecurityMode.to_bytes(2, byteorder = 'little', signed=False)
		t += self.DialectRevision.value.to_bytes(2, byteorder = 'little', signed=False)
		t += self.NegotiateContextCount.to_bytes(2, byteorder = 'little', signed=False)
		t += self.ServerGuid.to_bytes()
		t += self.Capabilities.to_bytes(4, byteorder = 'little', signed=False)
		t += self.MaxTransactSize.to_bytes(4, byteorder = 'little', signed=False)
		t += self.MaxReadSize.to_bytes(4, byteorder = 'little', signed=False)
		t += self.MaxWriteSize.to_bytes(4, byteorder = 'little', signed=False)
		t += datetime2timestamp(self.SystemTime)
		t += datetime2timestamp(self.ServerStartTime)

		t += self.SecurityBufferOffset.to_bytes(2, byteorder = 'little', signed=False)
		t += self.SecurityBufferLength.to_bytes(2, byteorder = 'little', signed=False)
		t += self.NegotiateContextOffset.to_bytes(4, byteorder = 'little', signed=False)
		t += self.Buffer

		if self.NegotiateContextCount > 0:
			for ngctx in self.NegotiateContextList:
				t+= ngctx.to_bytes()
				#PADDING!
				q,m = divmod(len(t)+64,8)
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
