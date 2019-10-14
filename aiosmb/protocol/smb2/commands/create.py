import io
import enum

from aiosmb.wintypes.fscc.FileAttributes import FileAttributes

class OplockLevel(enum.Enum):
	SMB2_OPLOCK_LEVEL_NONE = 0x00 #No oplock is requested.
	SMB2_OPLOCK_LEVEL_II = 0x01 #A level II oplock is requested.
	SMB2_OPLOCK_LEVEL_EXCLUSIVE = 0x08 #An exclusive oplock is requested.
	SMB2_OPLOCK_LEVEL_BATCH = 0x09 #A batch oplock is requested.
	SMB2_OPLOCK_LEVEL_LEASE = 0xFF #A lease is requested. If set, the request packet MUST contain an SMB2_CREATE_REQUEST_LEASE (section 2.2.13.2.8) create conte

class ImpersonationLevel(enum.Enum):
	Anonymous = 0x00000000 #The application-requested impersonation level is Anonymous.
	Identification = 0x00000001 #The application-requested impersonation level is Identification.
	Impersonation = 0x00000002 # The application-requested impersonation level is Impersonation.
	Delegate = 0x00000003 #The application-requested impersonation level is Delegate.

class ShareAccess(enum.IntFlag):
	FILE_SHARE_READ = 0x00000001 # When set, indicates that other opens are allowed to read this file while this open is present. This bit MUST NOT be set for a named pipe or a printer file. Each open creates a new instance of a named pipe. Likewise, opening a printer file always creates a new file.
	FILE_SHARE_WRITE = 0x00000002 # When set, indicates that other opens are allowed to write this file while this open is present. This bit MUST NOT be set for a named pipe or a printer file. Each open creates a new instance of a named pipe. Likewise, opening a printer file always creates a new file.
	FILE_SHARE_DELETE = 0x00000004 #When set, indicates that other opens are allowed to delete or rename this file while this open is present. This bit MUST NOT be set for a named pipe or a printer file. Each open creates a new instance of a named pipe. Likewise, opening a printer file always creates a new file.

class CreateDisposition(enum.Enum):
	FILE_SUPERSEDE = 0x00000000 #If the file already exists, supersede it. Otherwise, create the file. This value SHOULD NOT be used for a printer object.<30>
	FILE_OPEN = 0x00000001 #If the file already exists, return success; otherwise, fail the operation. MUST NOT be used for a printer object.
	FILE_CREATE = 0x00000002 #If the file already exists, fail the operation; otherwise, create the file.
	FILE_OPEN_IF = 0x00000003 #Open the file if it already exists; otherwise, create the file. This value SHOULD NOT be used for a printer object.<31>
	FILE_OVERWRITE = 0x00000004 #Overwrite the file if it already exists; otherwise, fail the operation. MUST NOT be used for a printer object.
	FILE_OVERWRITE_IF = 0x00000005 #Overwrite the file if it already exists; otherwise, create the file. This value SHOULD NOT be used for a printer object.<32>

class CreateOptions(enum.IntFlag):
	FILE_DIRECTORY_FILE = 0x00000001 #The file being created or opened is a directory file. With this flag, the CreateDisposition field MUST be set to FILE_CREATE, FILE_OPEN_IF, or FILE_OPEN. With this flag, only the following CreateOptions values are valid: FILE_WRITE_THROUGH, FILE_OPEN_FOR_BACKUP_INTENT, FILE_DELETE_ON_CLOSE, and FILE_OPEN_REPARSE_POINT. If the file being created or opened already exists and is not a directory file and FILE_CREATE is specified in the CreateDisposition field, then the server MUST fail the request with STATUS_OBJECT_NAME_COLLISION. If the file being created or opened already exists and is not a directory file and FILE_CREATE is not specified in the CreateDisposition field, then the server MUST fail the request with STATUS_NOT_A_DIRECTORY. The server MUST fail an invalid CreateDisposition field or an invalid combination of CreateOptions flags with STATUS_INVALID_PARAMETER.
	FILE_WRITE_THROUGH = 0x00000002 #The server performs file write-through; file data is written to the underlying storage before completing the write operation on this open.
	FILE_SEQUENTIAL_ONLY = 0x00000004 #This indicates that the application intends to read or write at sequential offsets using this handle, so the server SHOULD optimize for sequential access. However, the server MUST accept any access pattern. This flag value is incompatible with the FILE_RANDOM_ACCESS value.
	FILE_NO_INTERMEDIATE_BUFFERING = 0x00000008 #File buffering is not performed on this open; file data is not retained in memory upon writing it to, or reading it from, the underlying storage.
	FILE_SYNCHRONOUS_IO_ALERT = 0x00000010 #This bit SHOULD be set to 0 and MUST be ignored by the server.<34>
	FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020 #This bit SHOULD be set to 0 and MUST be ignored by the server.<35>
	FILE_NON_DIRECTORY_FILE = 0x00000040 #If the name of the file being created or opened matches with an existing directory file, the server MUST fail the request with STATUS_FILE_IS_A_DIRECTORY. This flag MUST NOT be used with FILE_DIRECTORY_FILE or the server MUST fail the request with STATUS_INVALID_PARAMETER.
	FILE_COMPLETE_IF_OPLOCKED = 0x00000100 #This bit SHOULD be set to 0 and MUST be ignored by the server.<36>
	FILE_NO_EA_KNOWLEDGE = 0x00000200 #The caller does not understand how to handle extended attributes. If the request includes an SMB2_CREATE_EA_BUFFER create context, then the server MUST fail this request with STATUS_ACCESS_DENIED. If extended attributes with the FILE_NEED_EA flag (see [MS-FSCC] section 2.4.15) set are associated with the file being opened, then the server MUST fail this request with STATUS_ACCESS_DENIED.
	FILE_RANDOM_ACCESS = 0x00000800 #This indicates that the application intends to read or write at random offsets using this handle, so the server SHOULD optimize for random access. However, the server MUST accept any access pattern. This flag value is incompatible with the FILE_SEQUENTIAL_ONLY value. If both FILE_RANDOM_ACCESS and FILE_SEQUENTIAL_ONLY are set, then FILE_SEQUENTIAL_ONLY is ignored.
	FILE_DELETE_ON_CLOSE = 0x00001000 #The file MUST be automatically deleted when the last open request on this file is closed. When this option is set, the DesiredAccess field MUST include the DELETE flag. This option is often used for temporary files.
	FILE_OPEN_BY_FILE_ID = 0x00002000 #This bit SHOULD be set to 0 and the server MUST fail the request with a STATUS_NOT_SUPPORTED error if this bit is set.<37>
	FILE_OPEN_FOR_BACKUP_INTENT = 0x00004000 #The file is being opened for backup intent. That is, it is being opened or created for the purposes of either a backup or a restore operation. The server can check to ensure that the caller is capable of overriding whatever security checks have been placed on the file to allow a backup or restore operation to occur. The server can check for access rights to the file before checking the DesiredAccess field.
	FILE_NO_COMPRESSION = 0x00008000 #The file cannot be compressed. This bit is ignored when FILE_DIRECTORY_FILE is set in CreateOptions.
	FILE_OPEN_REMOTE_INSTANCE = 0x00000400 #This bit SHOULD be set to 0 and MUST be ignored by the server.
	FILE_OPEN_REQUIRING_OPLOCK = 0x00010000 #This bit SHOULD be set to 0 and MUST be ignored by the server.
	FILE_DISALLOW_EXCLUSIVE = 0x00020000 #This bit SHOULD be set to 0 and MUST be ignored by the server.
	FILE_RESERVE_OPFILTER = 0x00100000 #This bit SHOULD be set to 0 and the server MUST fail the request with a STATUS_NOT_SUPPORTED error if this bit is set.<38>
	FILE_OPEN_REPARSE_POINT = 0x00200000 #If the file or directory being opened is a reparse point, open the reparse point itself rather than the target that the reparse point references.
	FILE_OPEN_NO_RECALL = 0x00400000 #In an HSM (Hierarchical Storage Management) environment, this flag means the file SHOULD NOT be recalled from tertiary storage such as tape. The recall can take several minutes. The caller can specify this flag to avoid those delays.
	FILE_OPEN_FOR_FREE_SPACE_QUERY = 0x00800000 #Open file to query for free space. The client SHOULD set this to 0 and the server MUST ignore it.<39>


class CreateAction(enum.Enum):
	FILE_SUPERSEDED = 0x00000000 # An existing file was deleted and a new file was created in its place.
	FILE_OPENED = 0x00000001 #An existing file was opened.
	FILE_CREATED = 0x00000002 #A new file was created.
	FILE_OVERWRITTEN = 0x00000003

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e8fb45c1-a03d-44ca-b7ae-47385cfd7997
class CREATE_REQ:
	def __init__(self):
		self.StructureSize = 57
		self.SecurityFlags  = 0
		self.RequestedOplockLevel  = None
		self.ImpersonationLevel  = None
		self.SmbCreateFlags  = 0
		self.Reserved   = 0
		self.DesiredAccess    = None
		self.FileAttributes     = None
		self.ShareAccess      = None
		self.CreateDisposition       = None
		self.CreateOptions        = None
		self.NameOffset         = None
		self.NameLength          = None
		self.CreateContextsOffset = 0
		self.CreateContextsLength = 0
		
		self.Buffer = None
		
		#high-level
		self.Name = None
		self.CreateContext = None

	def to_bytes(self):
		if self.Name is not None:
			t_name = self.Name.encode('utf-16-le')
			self.Buffer = t_name
			self.NameOffset = 64 + 2 + 1 + 1 + 4 + 8 + 8 + 4 + 4 + 4 + 4 + 4 + 2 + 2 + 4 + 4
			self.NameLength = len(t_name)
			
		if self.CreateContext:
			t_ctx = self.CreateContext.to_bytes()
			self.CreateContextsLength = len(t_ctx)
			
			pos = curself.NameOffset + self.NameLength
			t_m = pos % 8
			if t_m != 0:
				pad = b'\x00' * (8 - t_m)
				self.Buffer += pad
				self.Buffer +=t_ctx
				self.CreateContextsOffset = pos + len(pad)
			else:
				self.Buffer += t_ctx
				self.CreateContextsOffset = pos
			
		
		t  = self.StructureSize.to_bytes(2, byteorder='little', signed = False)
		t += self.SecurityFlags.to_bytes(1, byteorder='little', signed = False)
		t += self.RequestedOplockLevel.value.to_bytes(1, byteorder='little', signed = False)
		t += self.ImpersonationLevel.value.to_bytes(4, byteorder='little', signed = False)
		t += self.SmbCreateFlags.to_bytes(8, byteorder='little', signed = False)
		t += self.Reserved.to_bytes(8, byteorder='little', signed = False)
		t += self.DesiredAccess.to_bytes(4, byteorder='little', signed = False)
		t += self.FileAttributes.to_bytes(4, byteorder='little', signed = False)
		t += self.ShareAccess.to_bytes(4, byteorder='little', signed = False)
		t += self.CreateDisposition.value.to_bytes(4, byteorder='little', signed = False)
		t += self.CreateOptions.to_bytes(4, byteorder='little', signed = False)
		t += self.NameOffset.to_bytes(2, byteorder='little', signed = False)
		t += self.NameLength.to_bytes(2, byteorder='little', signed = False)
		t += self.CreateContextsOffset.to_bytes(4, byteorder='little', signed = False)
		t += self.CreateContextsLength.to_bytes(4, byteorder='little', signed = False)
		t += self.Buffer
		t += b'\x00'
		return t

	@staticmethod
	def from_bytes(bbuff):
		return CREATE_REQ.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		msg = CREATE_REQ()
		msg.StructureSize = int.from_bytes(buff.read(2), byteorder='little')
		assert msg.StructureSize == 57
		msg.SecurityFlags = int.from_bytes(buff.read(1), byteorder='little')
		msg.RequestedOplockLevel = OplockLevel(int.from_bytes(buff.read(1), byteorder='little'))
		msg.ImpersonationLevel = ImpersonationLevel(int.from_bytes(buff.read(4), byteorder = 'little'))
		msg.SmbCreateFlags = int.from_bytes(buff.read(8), byteorder = 'little')
		msg.Reserved = int.from_bytes(buff.read(8), byteorder = 'little')
		msg.DesiredAccess = FileAccessMask(int.from_bytes(buff.read(4), byteorder = 'little'))
		msg.FileAttributes = FileAttributes(int.from_bytes(buff.read(4), byteorder = 'little'))
		msg.ShareAccess = ShareAccess(int.from_bytes(buff.read(4), byteorder = 'little'))
		msg.CreateDisposition = CreateDisposition(int.from_bytes(buff.read(4), byteorder = 'little'))
		msg.CreateOptions  = CreateOptions(int.from_bytes(buff.read(4), byteorder = 'little'))
		msg.NameOffset = int.from_bytes(buff.read(2), byteorder = 'little') #first 8-byte aligned  !!!!!!
		msg.NameLength = int.from_bytes(buff.read(2), byteorder = 'little')
		msg.CreateContextsOffset = int.from_bytes(buff.read(4), byteorder = 'little') #first 8-byte aligned  !!!!!!
		msg.CreateContextsLength = int.from_bytes(buff.read(4), byteorder = 'little')
		
		if msg.NameLength > 0:
			buff.seek(msg.NameOffset, io.SEEK_SET)
			t = buff.read(msg.NameLength)
			msg.Name = t.decode('utf-16-le')
		
		if msg.CreateContextsLength > 0:
			buff.seek(msg.CreateContextsOffset, io.SEEK_SET)
			t = buff.read(msg.CreateContextsLength)
			msg.CreateContext = t #ADDITIONAL PARSING NEEDED BUT NOT YET IMPLEMENTED!!!! See: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/75364667-3a93-4e2c-b771-592d8d5e876d
		
		return msg

	def __repr__(self):
		t = '==== SMB2 CREATE REQ ====\r\n'
		t += 'StructureSize: %s\r\n' % self.StructureSize
		t += 'RequestedOplockLevel: %s\r\n' % self.RequestedOplockLevel
		t += 'ImpersonationLevel: %s\r\n' % self.ImpersonationLevel
		t += 'DesiredAccess: %s\r\n' % self.DesiredAccess
		t += 'FileAttributes: %s\r\n' % self.FileAttributes
		t += 'ShareAccess: %s\r\n' % self.ShareAccess
		t += 'CreateDisposition: %s\r\n' % self.CreateDisposition
		t += 'CreateOptions: %s\r\n' % self.CreateOptions
		t += 'Name: %s\r\n' % self.Name
		t += 'CreateContext: %s\r\n' % self.CreateContext
		return t
		
		
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/d166aa9e-0b53-410e-b35e-3933d8131927
class CREATE_REPLY:
	def __init__(self):
		self.StructureSize = 89
		self.OplockLevel = None
		self.Flags = 0
		self.CreateAction = None
		self.CreationTime   = 0
		self.LastAccessTime    = 0
		self.LastWriteTime     = None
		self.ChangeTime      = None
		self.AllocationSize       = None
		self.EndofFile        = None
		self.FileAttributes         = None
		self.Reserved2          = 0
		self.FileId           = None
		self.CreateContextsOffset = None
		self.CreateContextsLength = None
		
		self.Buffer = b''
		
		#high-level
		self.CreateContext = None

	def to_bytes(self):
		# TODO	
		#return t
		pass

	@staticmethod
	def from_bytes(bbuff):
		return CREATE_REPLY.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		msg = CREATE_REPLY()
		msg.StructureSize = int.from_bytes(buff.read(2), byteorder='little')
		assert msg.StructureSize == 89
		msg.OplockLevel  = OplockLevel(int.from_bytes(buff.read(1), byteorder='little'))
		msg.Flags  = CreateOptions(int.from_bytes(buff.read(1), byteorder='little'))
		msg.CreateAction  = CreateAction(int.from_bytes(buff.read(4), byteorder = 'little'))
		
		msg.CreationTime  = int.from_bytes(buff.read(8), byteorder = 'little')
		msg.LastAccessTime  = int.from_bytes(buff.read(8), byteorder = 'little')
		msg.LastWriteTime  = int.from_bytes(buff.read(8), byteorder = 'little')
		msg.ChangeTime  = int.from_bytes(buff.read(8), byteorder = 'little')
		msg.AllocationSize  = int.from_bytes(buff.read(8), byteorder = 'little')
		msg.EndofFile  = int.from_bytes(buff.read(8), byteorder = 'little')
		msg.FileAttributes   = FileAttributes(int.from_bytes(buff.read(4), byteorder = 'little'))
		msg.Reserved2  = int.from_bytes(buff.read(4), byteorder = 'little') #first 8-byte aligned  !!!!!!
		msg.FileId  = int.from_bytes(buff.read(16), byteorder = 'little')
		msg.CreateContextsOffset = int.from_bytes(buff.read(4), byteorder = 'little') #first 8-byte aligned  !!!!!!
		msg.CreateContextsLength = int.from_bytes(buff.read(4), byteorder = 'little')
		
		if msg.CreateContextsLength > 0:
			buff.seek(msg.CreateContextsOffset, io.SEEK_SET)
			t = buff.read(msg.CreateContextsLength)
			msg.CreateContext = t #ADDITIONAL PARSING NEEDED BUT NOT YET IMPLEMENTED!!!! See: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/75364667-3a93-4e2c-b771-592d8d5e876d
		
		return msg

	def __repr__(self):
		t = '==== SMB2 CREATE REPLY ====\r\n'
		t += 'StructureSize: %s\r\n' % self.StructureSize
		t += 'OplockLevel: %s\r\n' % self.OplockLevel
		t += 'Flags: %s\r\n' % self.Flags
		t += 'CreationTime: %s\r\n' % self.CreationTime
		t += 'LastAccessTime: %s\r\n' % self.LastAccessTime
		t += 'LastWriteTime: %s\r\n' % self.LastWriteTime
		t += 'ChangeTime: %s\r\n' % self.ChangeTime
		t += 'AllocationSize: %s\r\n' % self.AllocationSize
		t += 'EndofFile: %s\r\n' % self.EndofFile
		t += 'FileAttributes: %s\r\n' % self.FileAttributes
		t += 'Reserved2: %s\r\n' % self.Reserved2
		t += 'FileId: %s\r\n' % self.FileId
		t += 'CreateContextsOffset: %s\r\n' % self.CreateContextsOffset
		t += 'CreateContextsLength: %s\r\n' % self.CreateContextsLength
		return t