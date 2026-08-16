import enum
import io

from aiosmb.wintypes.fscc.structures._helpers import (
	as_int,
	decode_utf16,
	encode_utf16,
	read_exact,
)


class FileSystemAttributes(enum.IntFlag):
	NONE = 0x00000000
	FILE_CASE_SENSITIVE_SEARCH = 0x00000001
	FILE_CASE_PRESERVED_NAMES = 0x00000002
	FILE_UNICODE_ON_DISK = 0x00000004
	FILE_PERSISTENT_ACLS = 0x00000008
	FILE_FILE_COMPRESSION = 0x00000010
	FILE_VOLUME_QUOTAS = 0x00000020
	FILE_SUPPORTS_SPARSE_FILES = 0x00000040
	FILE_SUPPORTS_REPARSE_POINTS = 0x00000080
	FILE_SUPPORTS_REMOTE_STORAGE = 0x00000100
	FILE_RETURNS_CLEANUP_RESULT_INFO = 0x00000200
	FILE_SUPPORTS_POSIX_UNLINK_RENAME = 0x00000400
	FILE_VOLUME_IS_COMPRESSED = 0x00008000
	FILE_SUPPORTS_OBJECT_IDS = 0x00010000
	FILE_SUPPORTS_ENCRYPTION = 0x00020000
	FILE_NAMED_STREAMS = 0x00040000
	FILE_READ_ONLY_VOLUME = 0x00080000
	FILE_SEQUENTIAL_WRITE_ONCE = 0x00100000
	FILE_SUPPORTS_TRANSACTIONS = 0x00200000
	FILE_SUPPORTS_HARD_LINKS = 0x00400000
	FILE_SUPPORTS_EXTENDED_ATTRIBUTES = 0x00800000
	FILE_SUPPORTS_OPEN_BY_FILE_ID = 0x01000000
	FILE_SUPPORTS_USN_JOURNAL = 0x02000000
	FILE_SUPPORTS_INTEGRITY_STREAMS = 0x04000000
	FILE_SUPPORTS_BLOCK_REFCOUNTING = 0x08000000
	FILE_SUPPORTS_SPARSE_VDL = 0x10000000
	FILE_DAX_VOLUME = 0x20000000
	FILE_SUPPORTS_GHOSTING = 0x40000000


class FileFsAttributeInformation:
	def __init__(self):
		self.FileSystemAttributes = FileSystemAttributes.NONE
		self.MaximumComponentNameLength = 255
		self.FileSystemNameLength = 0
		self.FileSystemName = ''

	def to_bytes(self):
		name = encode_utf16(self.FileSystemName, 'FileSystemName')
		self.FileSystemNameLength = len(name)
		t  = as_int(self.FileSystemAttributes).to_bytes(4, 'little')
		t += self.MaximumComponentNameLength.to_bytes(
			4, 'little', signed=True
		)
		t += self.FileSystemNameLength.to_bytes(4, 'little')
		t += name
		return t

	@staticmethod
	def from_bytes(data):
		return FileFsAttributeInformation.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		fixed = read_exact(buff, 12, 'FILE_FS_ATTRIBUTE_INFORMATION')
		msg = FileFsAttributeInformation()
		msg.FileSystemAttributes = FileSystemAttributes(
			int.from_bytes(fixed[0:4], 'little')
		)
		msg.MaximumComponentNameLength = int.from_bytes(
			fixed[4:8], 'little', signed=True
		)
		msg.FileSystemNameLength = int.from_bytes(fixed[8:12], 'little')
		name = read_exact(
			buff,
			msg.FileSystemNameLength,
			'FILE_FS_ATTRIBUTE_INFORMATION FileSystemName',
		)
		msg.FileSystemName = decode_utf16(name, 'FileSystemName')
		return msg
