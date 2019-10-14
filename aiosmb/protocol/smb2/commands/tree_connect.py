import io
import enum

from aiosmb.wintypes.access_mask import *

#SMB 3.1.1 ONLY! Otherwise it's 0 as reserved!
class TreeConnectFlag(enum.IntFlag):
	SMB2_TREE_CONNECT_FLAG_CLUSTER_RECONNECT = 0x0001
	SMB2_TREE_CONNECT_FLAG_REDIRECT_TO_OWNER = 0x0002
	SMB2_TREE_CONNECT_FLAG_EXTENSION_PRESENT = 0x0004


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/832d2130-22e8-4afb-aafd-b30bb0901798
class TREE_CONNECT_REQ:
	def __init__(self):
		self.StructureSize = 9
		self.Flags = None
		self.PathOffset = None
		self.PathLength = None
		self.Buffer = None
		
		#high-level variable, not part of the spec!
		self.Path = None

	def to_bytes(self):
		if self.Path:
			self.Buffer = self.Path.encode('utf-16-le')
		
		self.PathLength = len(self.Buffer)
		self.PathOffset = 64 + 2 + 2 + 2 + 2 
		
		t  = self.StructureSize.to_bytes(2, byteorder='little', signed = False)
		t += self.Flags.to_bytes(2, byteorder='little', signed = False)
		t += self.PathOffset.to_bytes(2, byteorder='little', signed = False)
		t += self.PathLength.to_bytes(2, byteorder='little', signed = False)
		t += self.Buffer
		return t

	@staticmethod
	def from_bytes(bbuff):
		return TREE_CONNECT_REQ.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		msg = TREE_CONNECT_REQ()
		msg.StructureSize   = int.from_bytes(buff.read(2), byteorder='little')
		assert msg.StructureSize == 9
		msg.Flags = TreeConnectFlag(int.from_bytes(buff.read(2), byteorder='little'))
		msg.PathOffset = int.from_bytes(buff.read(2), byteorder='little')
		msg.PathLength = int.from_bytes(buff.read(2), byteorder = 'little')

		buff.seek(msg.PathOffset, io.SEEK_SET)
		msg.Buffer= buff.read(msg.PathLength)
		
		msg.Path = msg.Buffer.decode('utf-16-le')
		return msg

	def __repr__(self):
		t = '==== SMB2 TREE CONNECT REQ ====\r\n'
		t += 'StructureSize: %s\r\n' % self.StructureSize
		t += 'Flags: %s\r\n' % repr(self.Flags)
		t += 'PathOffset: %s\r\n' % self.PathOffset
		t += 'PathLength: %s\r\n' % self.PathLength
		t += 'Path: %s\r\n' % self.Path
		return t
		
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/dd34e26c-a75e-47fa-aab2-6efc27502e96
class ShareType(enum.Enum):
	DISK = 0x01
	PIPE = 0x02
	PRINT = 0x03
	
class ShareFlags(enum.IntFlag):
	SMB2_SHAREFLAG_MANUAL_CACHING = 0x00000000 #The client can cache files that are explicitly selected by the user for offline use.
	SMB2_SHAREFLAG_AUTO_CACHING = 0x00000010 #The client can automatically cache files that are used by the user for offline access.
	SMB2_SHAREFLAG_VDO_CACHING = 0x00000020 #The client can automatically cache files that are used by the user for offline access and can use those files in an offline mode even if the share is available.
	SMB2_SHAREFLAG_NO_CACHING = 0x00000030 #Offline caching MUST NOT occur.
	SMB2_SHAREFLAG_DFS = 0x00000001 #The specified share is present in a Distributed File System (DFS) tree structure. The server SHOULD set the SMB2_SHAREFLAG_DFS bit in the ShareFlags field if the per-share property Share.IsDfs is TRUE.
	SMB2_SHAREFLAG_DFS_ROOT = 0x00000002# The specified share is present in a DFS tree structure. The server SHOULD set the SMB2_SHAREFLAG_DFS_ROOT bit in the ShareFlags field if the per-share property Share.IsDfs is TRUE.
	SMB2_SHAREFLAG_RESTRICT_EXCLUSIVE_OPENS = 0x00000100 #The specified share disallows exclusive file opens that deny reads to an open file.
	SMB2_SHAREFLAG_FORCE_SHARED_DELETE = 0x00000200 #The specified share disallows clients from opening files on the share in an exclusive mode that prevents the file from being deleted until the client closes the file.
	SMB2_SHAREFLAG_ALLOW_NAMESPACE_CACHING = 0x00000400 #The client MUST ignore this flag.
	SMB2_SHAREFLAG_ACCESS_BASED_DIRECTORY_ENUM = 0x00000800 #The server will filter directory entries based on the access permissions of the client.
	SMB2_SHAREFLAG_FORCE_LEVELII_OPLOCK = 0x00001000 #The server will not issue exclusive caching rights on this share.<27>
	SMB2_SHAREFLAG_ENABLE_HASH_V1 = 0x00002000 #The share supports hash generation for branch cache retrieval of data. For more information, see section 2.2.31.2. This flag is not valid for the SMB 2.0.2 dialect.
	SMB2_SHAREFLAG_ENABLE_HASH_V2 = 0x00004000 # The share supports v2 hash generation for branch cache retrieval of data. For more information, see section 2.2.31.2. This flag is not valid for the SMB 2.0.2 and SMB 2.1 dialects.
	SMB2_SHAREFLAG_ENCRYPT_DATA = 0x00008000 #The server requires encryption of remote file access messages on this share, per the conditions specified in section 3.3.5.2.11. This flag is only valid for the SMB 3.x dialect family.
	SMB2_SHAREFLAG_IDENTITY_REMOTING = 0x00040000 # The share supports identity remoting. The client can request remoted identity access for the share via the SMB2_REMOTED_IDENTITY_TREE_CONNECT context as specified in section 2.2.9.2.1.

class TreeCapabilities(enum.IntFlag):
	SMB2_SHARE_CAP_DFS = 0x00000008 #The specified share is present in a DFS tree structure. The server MUST set the SMB2_SHARE_CAP_DFS bit in the Capabilities field if the per-share property Share.IsDfs is TRUE.
	SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY = 0x00000010 #The specified share is continuously available. This flag is only valid for the SMB 3.x dialect family.
	SMB2_SHARE_CAP_SCALEOUT = 0x00000020 #The specified share is present on a server configuration which facilitates faster recovery of durable handles. This flag is only valid for the SMB 3.x dialect family.
	SMB2_SHARE_CAP_CLUSTER = 0x00000040 #The specified share is present on a server configuration which provides monitoring of the availability of share through the Witness service specified in [MS-SWN]. This flag is only valid for the SMB 3.x dialect family.
	SMB2_SHARE_CAP_ASYMMETRIC = 0x00000080 #The specified share is present on a server configuration that allows dynamic changes in the ownership of the share. This flag is not valid for the SMB 2.0.2, 2.1, and 3.0 dialects.
	SMB2_SHARE_CAP_REDIRECT_TO_OWNER = 0x00000100 #The specified share is present on a server configuration that supports synchronous share level redirection via a Share Redirect error context response (section 2.2.2.2.2). This flag is not valid for SMB 2.0.2, 2.1, 3.0, and 3.0.2 dialects.


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/dd34e26c-a75e-47fa-aab2-6efc27502e96
class TREE_CONNECT_REPLY():
	def __init__(self):
		self.StructureSize = 16
		self.ShareType = None
		self.Reserved = None
		self.ShareFlags = None
		self.Capabilities = None
		self.MaximalAccess = None
		
		#high-level variable, not part of the spec!
		self.Path = None

	def to_bytes(self):
		if self.Path:
			self.Buffer = self.Path.encode('utf-16-le')
		
		self.PathLength = len(self.Buffer)
		self.PathOffset = 64 + 2 + 2 + 2 + 2 
		
		t  = self.StructureSize.to_bytes(2, byteorder='little', signed = False)
		t += self.Flags.to_bytes(2, byteorder='little', signed = False)
		t += self.PathOffset.to_bytes(2, byteorder='little', signed = False)
		t += self.PathLength.to_bytes(2, byteorder='little', signed = False)
		t += self.Buffer
		return t

	@staticmethod
	def from_bytes(bbuff):
		return TREE_CONNECT_REPLY.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		msg = TREE_CONNECT_REPLY()
		msg.StructureSize   = int.from_bytes(buff.read(2), byteorder='little')
		assert msg.StructureSize == 16
		msg.ShareType = ShareType(int.from_bytes(buff.read(1), byteorder='little'))
		msg.Reserved = int.from_bytes(buff.read(1), byteorder='little')
		msg.ShareFlags = ShareFlags(int.from_bytes(buff.read(4), byteorder = 'little'))
		msg.Capabilities = TreeCapabilities(int.from_bytes(buff.read(4), byteorder = 'little'))
		msg.MaximalAccess = FileAccessMask(int.from_bytes(buff.read(4), byteorder = 'little'))

		return msg

	def __repr__(self):
		t = '==== SMB2 TREE CONNECT REPLY ====\r\n'
		t += 'StructureSize: %s\r\n' % self.StructureSize
		t += 'ShareType: %s\r\n' % self.ShareType.value
		t += 'ShareFlags: %s\r\n' % self.ShareFlags
		t += 'Capabilities: %s\r\n' % self.Capabilities
		t += 'MaximalAccess: %s\r\n' % self.MaximalAccess
		return t