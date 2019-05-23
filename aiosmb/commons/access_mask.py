import enum


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/77b36d0f-6016-458a-a7a0-0f4a72ae1534
# File_Pipe_Printer_Access_Mask
class FileAccessMask(enum.IntFlag):
	FILE_READ_DATA = 0x00000001 #This value indicates the right to read data from the file or named pipe.
	FILE_WRITE_DATA = 0x00000002 #This value indicates the right to write data into the file or named pipe beyond the end of the file.
	FILE_APPEND_DATA = 0x00000004 #This value indicates the right to append data into the file or named pipe.
	FILE_READ_EA = 0x00000008 #This value indicates the right to read the extended attributes of the file or named pipe.
	FILE_WRITE_EA = 0x00000010 #This value indicates the right to write or change the extended attributes to the file or named pipe.
	FILE_DELETE_CHILD = 0x00000040 #This value indicates the right to delete entries within a directory.
	FILE_EXECUTE = 0x00000020 #This value indicates the right to execute the file.
	FILE_READ_ATTRIBUTES = 0x00000080 #This value indicates the right to read the attributes of the file.
	FILE_WRITE_ATTRIBUTES = 0x00000100 #This value indicates the right to change the attributes of the file.
	DELETE = 0x00010000 #This value indicates the right to delete the file.
	READ_CONTROL = 0x00020000 #This value indicates the right to read the security descriptor for the file or named pipe.
	WRITE_DAC = 0x00040000 #This value indicates the right to change the discretionary access control list (DACL) in the security descriptor for the file or named pipe. For the DACL data structure, see ACL in [MS-DTYP].
	WRITE_OWNER = 0x00080000 #This value indicates the right to change the owner in the security descriptor for the file or named pipe.
	SYNCHRONIZE = 0x00100000 #SMB2 clients set this flag to any value.<40> #SMB2 servers SHOULD<41> ignore this flag.
	ACCESS_SYSTEM_SECURITY = 0x01000000 #This value indicates the right to read or change the system access control list (SACL) in the security descriptor for the file or named pipe. For the SACL data structure, see ACL in [MS-DTYP].<42>
	MAXIMUM_ALLOWED = 0x02000000 #This value indicates that the client is requesting an open to the file with the highest level of access the client has on this file. If no access is granted for the client on this file, the server MUST fail the open with STATUS_ACCESS_DENIED.
	GENERIC_ALL = 0x10000000 #This value indicates a request for all the access flags that are previously listed except MAXIMUM_ALLOWED and ACCESS_SYSTEM_SECURITY.
	GENERIC_EXECUTE = 0x20000000 #This value indicates a request for the following combination of access flags listed above: FILE_READ_ATTRIBUTES| FILE_EXECUTE| SYNCHRONIZE| READ_CONTROL.
	GENERIC_WRITE = 0x40000000 #This value indicates a request for the following combination of access flags listed above: FILE_WRITE_DATA| FILE_APPEND_DATA| FILE_WRITE_ATTRIBUTES| FILE_WRITE_EA| SYNCHRONIZE| READ_CONTROL.
	GENERIC_READ = 0x80000000 #This value indicates a request for the following combination of access flags listed above: FILE_READ_DATA| FILE_READ_ATTRIBUTES| FILE_READ_EA| SYNCHRONIZE| READ_CONTROL.

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/0a5934b1-80f1-4da0-b1bf-5e021c309b71
class DirectoryAccessMask(enum.IntFlag):
	FILE_LIST_DIRECTORY = 0x00000001 #This value indicates the right to enumerate the contents of the directory.
	FILE_ADD_FILE = 0x00000002 #This value indicates the right to create a file under the directory.
	FILE_ADD_SUBDIRECTORY = 0x00000004 #This value indicates the right to add a sub-directory under the directory.
	FILE_READ_EA = 0x00000008 #This value indicates the right to read the extended attributes of the directory.
	FILE_WRITE_EA = 0x00000010 #This value indicates the right to write or change the extended attributes of the directory.
	FILE_TRAVERSE = 0x00000020 #This value indicates the right to traverse this directory if the server enforces traversal checking.
	FILE_DELETE_CHILD = 0x00000040 #This value indicates the right to delete the files and directories within this directory.
	FILE_READ_ATTRIBUTES = 0x00000080 #This value indicates the right to read the attributes of the directory.
	FILE_WRITE_ATTRIBUTES = 0x00000100 #This value indicates the right to change the attributes of the directory.
	DELETE = 0x00010000 #This value indicates the right to delete the directory.
	READ_CONTROL = 0x00020000 #This value indicates the right to read the security descriptor for the directory.
	WRITE_DAC = 0x00040000 #This value indicates the right to change the DACL in the security descriptor for the directory. For the DACL data structure, see ACL in [MS-DTYP].
	WRITE_OWNER = 0x00080000 #This value indicates the right to change the owner in the security descriptor for the directory.
	SYNCHRONIZE = 0x00100000 #SMB2 clients set this flag to any value.<43> SMB2 servers SHOULD<44> ignore this flag.
	ACCESS_SYSTEM_SECURITY = 0x01000000 #This value indicates the right to read or change the SACL in the security descriptor for the directory. For the SACL data structure, see ACL in [MS-DTYP].<45>
	MAXIMUM_ALLOWED = 0x02000000 #This value indicates that the client is requesting an open to the directory with the highest level of access the client has on this directory. If no access is granted for the client on this directory, the server MUST fail the open with STATUS_ACCESS_DENIED.
	GENERIC_ALL = 0x10000000 #This value indicates a request for all the access flags that are listed above except MAXIMUM_ALLOWED and ACCESS_SYSTEM_SECURITY.
	GENERIC_EXECUTE = 0x20000000 #This value indicates a request for the following access flags listed above: FILE_READ_ATTRIBUTES| FILE_TRAVERSE| SYNCHRONIZE| READ_CONTROL.
	GENERIC_WRITE = 0x40000000 #This value indicates a request for the following access flags listed above: FILE_ADD_FILE| FILE_ADD_SUBDIRECTORY| FILE_WRITE_ATTRIBUTES| FILE_WRITE_EA| SYNCHRONIZE| READ_CONTROL.
	GENERIC_READ = 0x80000000 #This value indicates a request for the following access flags listed above: FILE_LIST_DIRECTORY| FILE_READ_ATTRIBUTES| FILE_READ_EA| SYNCHRONIZE| READ_CONTROL.
