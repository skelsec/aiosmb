import enum


class SMB2HeaderFlag(enum.IntFlag):
	SMB2_FLAGS_SERVER_TO_REDIR    = 0x00000001  # When set, indicates the message is a response rather than a request. This MUST be set on responses sent from the server to the client, and MUST NOT be set on requests sent from the client to the server.
	SMB2_FLAGS_ASYNC_COMMAND      = 0x00000002  # When set, indicates that this is an ASYNC SMB2 header. Always set for headers of the form described in this section.
	SMB2_FLAGS_RELATED_OPERATIONS = 0x00000004
	SMB2_FLAGS_SIGNED             = 0x00000008  # When set, indicates that this packet has been signed. The use of this flag is as specified in section 3.1.5.1.
	SMB2_FLAGS_PRIORITY_MASK      = 0x00000070  # This flag is only valid for the SMB 3.1.1 dialect. It is a mask for the requested I/O priority of the request, and it MUST be a value in the range 0 to 7.
	SMB2_FLAGS_DFS_OPERATIONS     = 0x10000000  # When set, indicates that this command is a Distributed File System (DFS) operation. The use of this flag is as specified in section 3.3.5.9.
	SMB2_FLAGS_REPLAY_OPERATION   = 0x20000000


