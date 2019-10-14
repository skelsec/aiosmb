import enum


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/ca28ec38-f155-4768-81d6-4bfeb8586fc9
class FileAttributes(enum.IntFlag):
	FILE_ATTRIBUTE_ARCHIVE = 0x00000020 #A file or directory that requires to be archived. Applications use this attribute to mark files for backup or removal.
	FILE_ATTRIBUTE_COMPRESSED = 0x00000800 #A file or directory that is compressed. For a file, all of the data in the file is compressed. For a directory, compression is the default for newly created files and subdirectories.
	FILE_ATTRIBUTE_DIRECTORY = 0x00000010 #This item is a directory
	FILE_ATTRIBUTE_ENCRYPTED = 0x00004000 #A file or directory that is encrypted. For a file, all data streams in the file are encrypted. For a directory, encryption is the default for newly created files and subdirectories.
	FILE_ATTRIBUTE_HIDDEN = 0x00000002 #A file or directory that is hidden. Files and directories marked with this attribute do not appear in an ordinary directory listing.
	FILE_ATTRIBUTE_NORMAL = 0x00000080 #A file that does not have other attributes set. This flag is used to clear all other flags by specifying it with no other flags set. #This flag MUST be ignored if other flags are set.<147>
	FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x00002000 #A file or directory that is not indexed by the content indexing service.
	FILE_ATTRIBUTE_OFFLINE = 0x00001000 #The data in this file is not available immediately. This attribute indicates that the file data is physically moved to offline storage. This attribute is used by Remote Storage, which is hierarchical storage management software.
	FILE_ATTRIBUTE_READONLY = 0x00000001 #A file or directory that is read-only. For a file, applications can read the file but cannot write to it or delete it. For a directory, applications cannot delete it, but applications can create and delete files from that directory.
	FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400 #A file or directory that has an associated reparse point.
	FILE_ATTRIBUTE_SPARSE_FILE = 0x00000200 #A file that is a sparse file.
	FILE_ATTRIBUTE_SYSTEM = 0x00000004 #A file or directory that the operating system uses a part of or uses exclusively.
	FILE_ATTRIBUTE_TEMPORARY = 0x00000100 #A file that is being used for temporary storage. The operating system can choose to store this file's data in memory rather than on mass storage, writing the data to mass storage only if data remains in the file when the file is closed.
	FILE_ATTRIBUTE_INTEGRITY_STREAM = 0x00008000 #A file or directory that is configured with integrity support. For a file, all data streams in the file have integrity support. For a directory, integrity support is the default for newly created files and subdirectories, unless the caller specifies otherwise.<148>
	FILE_ATTRIBUTE_NO_SCRUB_DATA = 0x00020000 #A file or directory that is configured to be excluded from the data integrity scan. For a directory configured with FILE_ATTRIBUTE_NO_SCRUB_DATA, the default for newly created files and subdirectories is to inherit the FILE_ATTRIBUTE_NO_SCRUB_DATA attribute.<149>
