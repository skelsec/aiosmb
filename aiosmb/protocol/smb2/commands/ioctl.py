import io
import enum
import ipaddress

class CtlCode(enum.Enum):
	FSCTL_DFS_GET_REFERRALS = 0x00060194
	FSCTL_PIPE_PEEK = 0x0011400C
	FSCTL_PIPE_WAIT = 0x00110018
	FSCTL_PIPE_TRANSCEIVE = 0x0011C017
	FSCTL_SRV_COPYCHUNK = 0x001440F2
	FSCTL_SRV_ENUMERATE_SNAPSHOTS = 0x00144064
	FSCTL_SRV_REQUEST_RESUME_KEY = 0x00140078
	FSCTL_SRV_READ_HASH = 0x001441bb
	FSCTL_SRV_COPYCHUNK_WRITE = 0x001480F2
	FSCTL_LMR_REQUEST_RESILIENCY = 0x001401D4
	FSCTL_QUERY_NETWORK_INTERFACE_INFO = 0x001401FC
	FSCTL_SET_REPARSE_POINT = 0x000900A4
	FSCTL_DFS_GET_REFERRALS_EX = 0x000601B0
	FSCTL_FILE_LEVEL_TRIM = 0x00098208
	FSCTL_VALIDATE_NEGOTIATE_INFO = 0x00140204

class IOCTLREQFlags(enum.IntFlag):
	IS_IOCTL = 0
	IS_FSCTL = 1

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5c03c9d6-15de-48a2-9835-8fb37f8a79d8
class IOCTL_REQ:
	def __init__(self):
		self.StructureSize = 57
		self.Reserved  = 0
		self.CtlCode  = None #must be CtlCode
		self.FileId  = None #bytes
		self.InputOffset  = 0
		self.InputCount   = 0
		self.MaxInputResponse = 0
		self.OutputOffset = 0
		self.OutputCount = 0
		self.MaxOutputResponse = 65535
		self.Flags = IOCTLREQFlags.IS_IOCTL
		self.Reserved2 = 0
		
		self.Buffer = None

	def to_bytes(self):
		if self.CtlCode not in [CtlCode.FSCTL_PIPE_PEEK, CtlCode.FSCTL_SRV_ENUMERATE_SNAPSHOTS, CtlCode.FSCTL_SRV_REQUEST_RESUME_KEY, CtlCode.FSCTL_QUERY_NETWORK_INTERFACE_INFO]:
			self.InputOffset = 64 + 40 + 16
			self.InputCount = len(self.Buffer)


		t  = self.StructureSize.to_bytes(2, byteorder='little', signed = False)
		t += self.Reserved.to_bytes(2, byteorder='little', signed = False)
		t += self.CtlCode.value.to_bytes(4, byteorder='little', signed = False)
		t += self.FileId
		t += self.InputOffset.to_bytes(4, byteorder='little', signed = False)
		t += self.InputCount.to_bytes(4, byteorder='little', signed = False)
		t += self.MaxInputResponse.to_bytes(4, byteorder='little', signed = False)
		t += self.OutputOffset.to_bytes(4, byteorder='little', signed = False)
		t += self.OutputCount.to_bytes(4, byteorder='little', signed = False)
		t += self.MaxOutputResponse.to_bytes(4, byteorder='little', signed = False)
		t += self.Flags.to_bytes(4, byteorder='little', signed = False)
		t += self.Reserved2.to_bytes(4, byteorder='little', signed = False)
		if self.CtlCode not in [CtlCode.FSCTL_PIPE_PEEK, CtlCode.FSCTL_SRV_ENUMERATE_SNAPSHOTS, CtlCode.FSCTL_SRV_REQUEST_RESUME_KEY, CtlCode.FSCTL_QUERY_NETWORK_INTERFACE_INFO]:
			t += self.Buffer
		
		return t

	@staticmethod
	def from_bytes(bbuff):
		return IOCTL_REQ.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		msg = IOCTL_REQ()
		msg.StructureSize = int.from_bytes(buff.read(2), byteorder='little')
		assert msg.StructureSize == 57
		msg.Reserved = int.from_bytes(buff.read(2), byteorder='little')
		msg.CtlCode = int.from_bytes(buff.read(4), byteorder='little')
		msg.FileId = int.from_bytes(buff.read(16), byteorder='little')
		msg.InputOffset = int.from_bytes(buff.read(4), byteorder='little')
		msg.InputCount = int.from_bytes(buff.read(4), byteorder='little')
		msg.MaxInputResponse = int.from_bytes(buff.read(4), byteorder='little')
		msg.OutputOffset = int.from_bytes(buff.read(4), byteorder='little')
		msg.OutputCount = int.from_bytes(buff.read(4), byteorder='little')
		msg.MaxOutputResponse = int.from_bytes(buff.read(4), byteorder='little')
		msg.Flags = int.from_bytes(buff.read(4), byteorder='little')
		msg.Reserved2 = int.from_bytes(buff.read(4), byteorder='little')

		if msg.InputCount > 0:
			raise NotImplementedError()
		
		return msg

	def __repr__(self):
		t = '==== SMB2 IOCTL REQ ====\r\n'
		return t


class SRV_COPYCHUNK:
	def __init__(self):
		self.SourceOffset = None
		self.TargetOffset = None
		self.Length = None
		self.Reserved = 0

	def to_bytes(self):
		t  = self.SourceOffset.to_bytes(8, byteorder='little', signed = False)
		t += self.TargetOffset.to_bytes(8, byteorder='little', signed = False)
		t += self.Length.to_bytes(4, byteorder='little', signed = False)
		t += self.Reserved.to_bytes(4, byteorder='little', signed = False)

class SRV_COPYCHUNK_COPY:
	def __init__(self):
		self.SourceKey = None #24 bytes obtained from the server in a SRV_REQUEST_RESUME_KEY Response (section 2.2.32.3),
		self.ChunkCount = None
		self.Reserved = 0
		self.Chunks = []

	def to_bytes(self):
		self.ChunkCount = len(self.Chunks)
		
		t  = self.SourceKey
		t += self.ChunkCount.to_bytes(4, byteorder='little', signed = False)
		t += self.Reserved.to_bytes(4, byteorder='little', signed = False)
		for chunk in self.Chunks:
			t += chunk.to_bytes()

class SRV_HASH_TYPE(enum.Enum):
	SRV_HASH_TYPE_PEER_DIST = 0x01

class HashVersion(enum.Enum):
	SRV_HASH_VER_1 = 0x00000001 #Branch cache version 1.
	SRV_HASH_VER_2 = 0x00000002 #Branch cache version 2. This value is only applicable for the SMB 3.x dialect family.

class HashRetrievalType(enum.Enum):
	SRV_HASH_RETRIEVE_HASH_BASED = 0x00000001 #The Offset field in the SRV_READ_HASH request is relative to the beginning of the Content Information File.
	SRV_HASH_RETRIEVE_FILE_BASED = 0x00000002 #The Offset field in the SRV_READ_HASH request is relative to the beginning of the file indicated by the FileId field in the IOCTL request. This value is only applicable for the SMB 3.x dialect family.


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/9d154482-5532-4424-be11-18c578893aa9
# TODO
class SRV_READ_HASH:
	def __init__(self):
		self.HashType = None
		self.HashVersion = None
		self.HashRetrievalType = 0
		self.Length = None
		self.Offset = None

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/17061634-f8d5-4367-a058-9b4f4a5d4d3c
# TODO
class NETWORK_RESILIENCY_REQUEST:
	def __init__(self):
		self.Timeout = None #4bytres, miliseconds
		self.Reserved = 0 # 4 bytes zero

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/261ec397-d692-4e3e-8bcd-c96ce02bb969
# TODO
class VALIDATE_NEGOTIATE_INFO:
	def __init__(self):
		self.Capabilities = None
		self.Guid = None
		self.SecurityMode = None
		self.DialectCount = None
		self.Dialects = None


class IOCTL_REPLY:
	def __init__(self):
		self.StructureSize = 49
		self.Reserved  = 0
		self.CtlCode  = None #must be CtlCode
		self.FileId  = None #bytes
		self.InputOffset  = 0
		self.InputCount   = 0
		self.MaxInputResponse    = 0
		self.OutputOffset = 0
		self.OutputCount = 0
		self.MaxOutputResponse = 0
		self.Flags = 0
		self.Reserved2 = 0
		
		self.Buffer = None

	@staticmethod
	def from_bytes(bbuff):
		return IOCTL_REPLY.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		msg = IOCTL_REPLY()
		msg.StructureSize = int.from_bytes(buff.read(2), byteorder='little')
		assert msg.StructureSize == 49
		msg.Reserved = int.from_bytes(buff.read(2), byteorder='little')
		msg.CtlCode = CtlCode(int.from_bytes(buff.read(4), byteorder='little'))
		msg.FileId = buff.read(16)
		msg.InputOffset = int.from_bytes(buff.read(4), byteorder='little')
		msg.InputCount = int.from_bytes(buff.read(4), byteorder='little')
		msg.OutputOffset = int.from_bytes(buff.read(4), byteorder='little')
		msg.OutputCount = int.from_bytes(buff.read(4), byteorder='little')
		msg.Flags = int.from_bytes(buff.read(4), byteorder='little')
		msg.Reserved2 = int.from_bytes(buff.read(4), byteorder='little')

		if msg.CtlCode == CtlCode.FSCTL_PIPE_WAIT:
			return msg
		elif msg.CtlCode == CtlCode.FSCTL_LMR_REQUEST_RESILIENCY:
			return msg
		elif msg.CtlCode == CtlCode.FSCTL_QUERY_NETWORK_INTERFACE_INFO:
			buff.seek(msg.OutputOffset)
			data = buff.read(msg.OutputCount)
			msg.Buffer = []
			while True:
				info = NETWORK_INTERFACE_INFO.from_bytes(data)
				msg.Buffer.append(info)
				if info.Next == 0:
					break
				data = data[info.Next:]
			return msg
		else:
			raise NotImplementedError()

	def __repr__(self):
		t = '==== SMB2 IOCTL REQ ====\r\n'
		return t

class NETWORK_INTERFACE_CAP(enum.IntFlag):
	RSS_CAPABLE = 0x00000001 #When set, specifies that the interface is RSS-capable.
	RDMA_CAPABLE = 0x00000002 #When set, specifies that the interface is RDMA-capable.

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/fcd862d1-1b85-42df-92b1-e103199f531f
class NETWORK_INTERFACE_INFO:
	def __init__(self):
		self.Next = None
		self.IfIndex = None
		self.Capability = None
		self.Reserved = None
		self.LinkSpeed = None
		self.SockAddr_Storage = None

	
	@staticmethod
	def from_bytes(bbuff):
		return NETWORK_INTERFACE_INFO.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		msg = NETWORK_INTERFACE_INFO()
		msg.Next = int.from_bytes(buff.read(4), byteorder='little')
		msg.IfIndex = int.from_bytes(buff.read(4), byteorder='little')
		msg.Capability = NETWORK_INTERFACE_CAP(int.from_bytes(buff.read(4), byteorder='little'))
		msg.Reserved = int.from_bytes(buff.read(4), byteorder='little')
		msg.LinkSpeed = int.from_bytes(buff.read(8), byteorder='little')
		msg.SockAddr_Storage = SOCKADDR_STORAGE.from_bytes(buff.read(128))
		return msg
		
class SOCKADDR_STORAGE_FAMILY(enum.Enum):
	InterNetwork = 0x0002 #When set, indicates an IPv4 address in the socket.
	InterNetworkV6 = 0x0017 #When set, indicates an IPv6 address in the socket.

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/4b77102f-769f-414d-b137-47cabfe8be8f
class SOCKADDR_STORAGE:
	def __init__(self):
		self.Family = None
		self.Addr = None

	@staticmethod
	def from_bytes(bbuff):
		return SOCKADDR_STORAGE.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		msg = SOCKADDR_STORAGE()
		msg.Family = SOCKADDR_STORAGE_FAMILY(int.from_bytes(buff.read(4), byteorder='little'))
		if msg.Family == SOCKADDR_STORAGE_FAMILY.InterNetwork:
			msg.Addr = ipaddress.ip_address(buff.read(4))
		if msg.Family == SOCKADDR_STORAGE_FAMILY.InterNetworkV6:
			msg.Addr = ipaddress.ip_address(buff.read(16))
		return msg

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/24bb31a3-72f4-4aa6-9296-1cfd3813d21a
class SRV_SNAPSHOT_ARRAY:
	def __init__(self):
		self.NumberOfSnapShots = None
		self.NumberOfSnapShotsReturned = None
		self.SnapShotArraySize = None
		self.SnapShots = []

	@staticmethod
	def from_bytes(bbuff):
		return SRV_SNAPSHOT_ARRAY.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		msg = SRV_SNAPSHOT_ARRAY()
		msg.NumberOfSnapShots = int.from_bytes(buff.read(4), byteorder='little')
		msg.NumberOfSnapShotsReturned = int.from_bytes(buff.read(4), byteorder='little')
		msg.SnapShotArraySize = int.from_bytes(buff.read(4), byteorder='little')
		msg.SnapShots = int.from_bytes(buff.read(4), byteorder='little')
		return msg
