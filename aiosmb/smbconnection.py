import enum
import asyncio
import hmac
import hashlib

from aiosmb.network.network import TCPSocket
from aiosmb.network.netbios_transport import NetBIOSTransport
from aiosmb.protocol.smb.command_codes import SMBCommand
from aiosmb.commons.ntstatus import NTStatus
from aiosmb.protocol.smb.header import SMBHeader, SMBHeaderFlags2Enum
from aiosmb.protocol.smb.message import SMBMessage
from aiosmb.protocol.smb.commands import *
from aiosmb.protocol.smb2.message import SMB2Message, SMB2Transform
from aiosmb.protocol.smb2.commands import *
from aiosmb.protocol.smb2.headers import *
from aiosmb.protocol.smb2.command_codes import *
from aiosmb.utils.guid import *
from aiosmb.commons.access_mask import *
from aiosmb.fscc.structures.fileinfoclass import *
from aiosmb.fscc.structures.FileFullDirectoryInformation import *
from aiosmb.fscc.FileAttributes import FileAttributes


from aiosmb.spnego.spnego import SPNEGO
from aiosmb.ntlm.auth_handler import NTLMAUTHHandler, Credential, NTLMHandlerSettings

class SMBDialect(enum.Enum):
	SMB1 = 'NT LM 0.12'
	SMB2_2 = 'SMB 2.002'
	SMB2_3 = 'SMB 2.???'

class SMBTarget:
	def __init__(self):
		self.ip = None
		self.port = None
		self.hostname = None
		self.spn = None
		
		
	def get_ip(self):
		return self.ip
	
	def get_port(self):
		return self.port

class SMBConnectionStatus(enum.Enum):
	NEGOTIATING = 'NEGOTIATING'
	SESSIONSETUP = 'SESSIONSETUP'
	RUNNING = 'RUNNING'
	
class TreeEntry:
	def __init__(self):
		self.share_name = None
		self.tree_id = None
		self.session_id = None
		self.number_of_users = None
		self.is_DFS = None
		self.is_CA = None
		self.is_scaleout = None
		self.encrypt = None
		self.maximal_access = None
		
	@staticmethod
	def from_tree_reply(reply, share_name):
		te = TreeEntry()
		te.share_name = share_name
		te.tree_id = reply.header.TreeId
		te.session_id = reply.header.SessionId
		te.number_of_users = 1
		te.is_DFS = TreeCapabilities.SMB2_SHARE_CAP_DFS in reply.command.Capabilities
		te.is_CA = TreeCapabilities.SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY in reply.command.Capabilities
		te.is_scaleout = TreeCapabilities.SMB2_SHARE_CAP_SCALEOUT in reply.command.Capabilities
		te.encrypt = ShareFlags.SMB2_SHAREFLAG_ENCRYPT_DATA in reply.command.ShareFlags
		te.maximal_access = reply.command.MaximalAccess 
		return te
	
class FileHandle:
	def __init__(self):
		self.file_id = None
		self.tree_id = None
		self.oplock_level = None
		self.is_durable = None
		self.is_resilient = None
		self.last_disconnect_time = None
		self.file_name = None
	
	@staticmethod	
	def from_create_reply(reply, tree_id, file_name, oplock_level):
		fh = FileHandle()
		fh.file_id = reply.command.FileId
		fh.tree_id = tree_id
		fh.oplock_level = oplock_level
		fh.is_durable = False
		fh.is_resilient = False
		fh.last_disconnect_time = 0
		fh.file_name = file_name
		return fh
	
class SMBConnection:
	"""
	Connection class for network connectivity and SMB messages management (sending/recieveing/singing/encrypting).
	
	
	"""
	def __init__(self, gssapi,dialects, shutdown_evt = asyncio.Event()):
		self.gssapi = gssapi
		self.shutdown_evt = shutdown_evt
		
		self.settings = None
		self.network_transport = None #this class is used by the netbios transport class, keeping it here also
		self.netbios_transport = None
		self.dialects = dialects #list of SMBDialect
		
		self.selected_dialect = None
		
		self.status = SMBConnectionStatus.NEGOTIATING
		
		self.OutstandingResponsesEvent = {}
		self.OutstandingRequests = {}
		self.OutstandingResponses = {}
		
		#two dicts for the same data, but with different lookup key
		self.TreeConnectTable_id = {}
		self.TreeConnectTable_share = {}
		
		self.FileHandleTable = {}
		
		self.SequenceWindow = 0
		self.MaxTransactSize = 0
		self.MaxReadSize = 0
		self.MaxWriteSize = 0
		self.ServerGuid = None
		self.RequireSigning = False
		self.ServerName = None
		self.ClientGUID = GUID.random()
		
		self.Dialect = 0
		self.SupportsFileLeasing = False
		self.SupportsMultiCredit = False
		
		self.SupportsDirectoryLeasing = False
		self.SupportsMultiChannel = False
		self.SupportsPersistentHandles = False
		self.SupportsEncryption = False
		self.ClientCapabilities = 0
		self.ServerCapabilities = 0
		self.ClientSecurityMode = 0
		self.ServerSecurityMode = 0
		
		self.SessionId = 0
		self.SessionKey = None
		
	async def __handle_smb_in(self):
		"""
		Waits from SMB messages from the NetBIOSTransport in_queue, and fills the connection table.
		This function started automatically when calling connect.
		"""
		while not self.shutdown_evt.is_set():
			msg = await self.netbios_transport.in_queue.get()
			
			print('__handle_smb_in got new message with Id %s' % msg.header.MessageId)
			
			if isinstance(msg, SMB2Transform):
				#message is encrypted
				#this point we should decrypt it and only store the decrypted part in the OutstandingResponses table
				#but for now we just thropw exception bc encryption is not implemented
				raise Exception('Encrypted SMBv2 message recieved, but encryption is not yet supported!')
			
			self.OutstandingResponses[msg.header.MessageId] = msg
			self.OutstandingResponsesEvent[msg.header.MessageId].set()
			
		
	async def connect(self, target):
		"""
		Establishes socket connection to the remote endpoint. Also starts the internal reading procedures.
		"""
		self.network_transport = TCPSocket(shutdown_evt = self.shutdown_evt)
		
		res = await asyncio.gather(*[self.network_transport.connect(target)], return_exceptions=True)
		print(res)
		
		self.netbios_transport = NetBIOSTransport(self.network_transport, shutdown_evt = self.shutdown_evt)
		res =  await asyncio.gather(*[self.netbios_transport.run()], return_exceptions=True)
		print(res)
		
		asyncio.ensure_future(self.__handle_smb_in())
		
	async def disconnect(self):
		await self.network_transport.disconnect()
		self.netbios_transport.stop()
		
		
	async def negotiate(self):
		"""
		Initiates protocol negotiation.
		First we send an SMB_COM_NEGOTIATE_REQ with our supported dialects
		"""
		
		#let's construct an SMBv1 SMB_COM_NEGOTIATE_REQ packet
		header = SMBHeader()
		header.Command  = SMBCommand.SMB_COM_NEGOTIATE
		header.Status   = NTStatus.STATUS_SUCCESS
		header.Flags    = 0
		header.Flags2   = SMBHeaderFlags2Enum.SMB_FLAGS2_UNICODE

		command = SMB_COM_NEGOTIATE_REQ()
		for dialect in self.dialects:
			command.Dialects.append(dialect.value)	
		
		msg = SMBMessage(header, command)
		#sending the nego packet
		print('Sending negotiate command')
		message_id = await self.sendSMB(msg)
		
		#recieveing reply, should be version2, because currently we dont support v1 :(
		msg = await self.recvSMB(message_id) #negotiate MessageId should be 1
	
		print('Message recieved!')
		print(repr(msg))
		
		if isinstance(msg, SMB2Message):
			self.selected_dialect = msg.command.DialectRevision
			print('Server selected dialect: %s' % self.selected_dialect)
			
		else:
			print('Server choose SMB v1 which is not supported currently')
			raise Exception('SMBv2 not supported!')
			
		self.status = SMBConnectionStatus.SESSIONSETUP
		
		"""
		input('2')
			
		### second round, with smb2 only this time
		command = NEGOTIATE_REQ()
		command.SecurityMode    = 1  #NegotiateSecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED
		command.Capabilities    = 0 #NegotiateCapabilities
		command.ClientGuid      = self.ClientGUID

		command.Dialects        = [NegotiateDialects.SMB202]
		
		header = SMB2Header_SYNC()
		header.Command  = SMB2Command.NEGOTIATE
		header.CreditReq = 0
		header.CreditCharge = 1
		
		msg = SMBMessage(header, command)
		message_id = await self.sendSMB(msg)
			
		rply = await self.recvSMB(message_id)
		print('session got reply!')
		print(rply)
		"""
		
	async def session_setup(self):
	
		command = SESSION_SETUP_REQ()
		command.Buffer, res = self.gssapi.authenticate(None)
		#input(command.Buffer)
	
		command.Flags = 0
		command.SecurityMode = NegotiateSecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED
		command.Capabilities = 0
		command.Channel      = 0
		command.PreviousSessionId    = 0
		
		header = SMB2Header_SYNC()
		header.Command  = SMB2Command.SESSION_SETUP
		header.CreditReq = 0
		
		msg = SMBMessage(header, command)
		message_id = await self.sendSMB(msg)
		
		
		rply = await self.recvSMB(message_id)
		print('session got reply!')
		print(rply)
		
		#setting the session id for the whole connection
		self.SessionId = rply.header.SessionId
		
		#print('sleeping')
		#await asyncio.sleep(10)
		
		command = SESSION_SETUP_REQ()
		command.Buffer, res = self.gssapi.authenticate(rply.command.Buffer)
		#command.Buffer = bytes.fromhex('a18201603082015ca2820158048201544e544c4d53535000030000001800180054000000d800d8006c00000008000800400000000c000c004800000000000000540000001000100044010000358288e05400450053005400760069006300740069006d00c82ea7bdfcdcd5cec3d334b868dd0a5050494b767738656b7b2efd49a006c439fc8d02471bc9b65e01010000000000004dc738e7060bd50150494b767738656b0000000001001200570049004e0032003000310039004100440002000800540045005300540003002600570049004e003200300031003900410044002e0074006500730074002e0063006f00720070000400120074006500730074002e0063006f00720070000500120074006500730074002e0063006f0072007000070008004dc738e7060bd50109001c0063006900660073002f00570049004e0032003000310039004100440000000000000000002553d29cafe2b7af5dbba19142ca0ab0')
		
		
		
		#input(command.Buffer)
	
		command.Flags = 0
		command.SecurityMode = NegotiateSecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED
		command.Capabilities = 0
		command.Channel      = 0
		command.PreviousSessionId    = 0
		
		header = SMB2Header_SYNC()
		header.Command  = SMB2Command.SESSION_SETUP
		header.CreditReq = 127
		
		msg = SMBMessage(header, command)
		message_id = await self.sendSMB(msg)
		
		rply = await self.recvSMB(message_id)
		print('session got reply2!')
		print(rply)
		
		self.SessionKey = self.gssapi.get_session_key()
		
		
		#ADD CHECKS HERE FOR SUCCSESS!
		self.status = SMBConnectionStatus.RUNNING
		
		
	async def recvSMB(self, message_id = None):
		"""
		Returns an SMB message from the outstandingresponse dict, OR waits until the expected message_id appears.
		If message_id is None if will pop the first message from the outstandingresponse OR wait for the next available message.
		"""
		if message_id not in self.OutstandingResponses:
			print('Waiting on messageID : %s' % message_id)
			await self.OutstandingResponsesEvent[message_id].wait()
		
		msg = self.OutstandingResponses.pop(message_id)
		
		if message_id in self.OutstandingResponsesEvent:
			del self.OutstandingResponsesEvent[message_id]
		
		return msg
		
		
	def sign_message(self, msg):
		if self.selected_dialect in [NegotiateDialects.SMB202]:
			if self.SessionKey:
				msg.header.Flags = msg.header.Flags ^ SMB2HeaderFlag.SMB2_FLAGS_SIGNED ##maybe move this flag settings to sendsmb since singing is determined there?
				print('Singing with key: %s' % repr(self.SessionKey))
				print('Singing data: %s' % repr(msg.to_bytes()))
				digest = hmac.new(self.SessionKey, msg.to_bytes(), hashlib.sha256).digest()
				print('Digest: %s' % repr(digest[:16].hex()))
				msg.header.Signature = digest[:16]
				
		else:
			raise Exception('ONLY certain dialect supported!')
		
		
	async def sendSMB(self, msg):
		"""
		Sends an SMB message to teh remote endpoint.
		
		Returns: MessageId integer
		"""
		if self.status == SMBConnectionStatus.NEGOTIATING:
			#creating an event for outstanding response
			self.OutstandingResponsesEvent[0] = asyncio.Event()
			await self.netbios_transport.out_queue.put(msg)
			self.SequenceWindow += 1
			return 0
		
		if msg.header.Command is not SMB2Command.CANCEL:
			msg.header.MessageId = self.SequenceWindow
			self.SequenceWindow += 1
		
		msg.header.SessionId = self.SessionId
		
		if not msg.header.CreditCharge:
			msg.header.CreditCharge = 1
		
		if self.status != SMBConnectionStatus.SESSIONSETUP:
			msg.header.CreditReq = 127
		
		message_id = msg.header.MessageId
		
		#signing goes here
		self.sign_message(msg)
		
		#encryption goes here
		
		#creating an event for outstanding response
		self.OutstandingResponsesEvent[message_id] = asyncio.Event()
		
		await self.netbios_transport.out_queue.put(msg)
		
		return message_id
		
	async def tree_connect(self, share_name):
		"""
		share_name MUST be in "\\server\share" format! Server can be NetBIOS name OR IP4 OR IP6 OR FQDN
		"""
		
		command = TREE_CONNECT_REQ()
		command.Path = share_name
		command.Flags = 0
		
		header = SMB2Header_SYNC()
		header.Command  = SMB2Command.TREE_CONNECT
		
		msg = SMBMessage(header, command)
		message_id = await self.sendSMB(msg)
		
		rply = await self.recvSMB(message_id)
		print('session got reply2!')
		print(rply)
		
		te = TreeEntry.from_tree_reply(rply, share_name)
		self.TreeConnectTable_id[rply.header.TreeId] = te
		self.TreeConnectTable_share[share_name] = te
		
		
		return te
		
	async def create(self, tree_id, file_path, desired_access, share_mode, create_options, create_disposition, file_attrs, impresonation_level = ImpersonationLevel.Impersonation, oplock_level = OplockLevel.SMB2_OPLOCK_LEVEL_NONE, create_contexts = None):
		if tree_id not in self.TreeConnectTable_id:
			raise Exception('Unknown Tree ID!')
		
		command = CREATE_REQ()
		command.RequestedOplockLevel  = oplock_level
		command.ImpersonationLevel  = impresonation_level
		command.DesiredAccess    = desired_access
		command.FileAttributes     = file_attrs
		command.ShareAccess      = share_mode
		command.CreateDisposition       = create_disposition
		command.CreateOptions        = create_options
		command.Name = file_path
		command.CreateContext = create_contexts
		
		header = SMB2Header_SYNC()
		header.Command  = SMB2Command.CREATE
		header.TreeId = tree_id
		
		msg = SMBMessage(header, command)
		message_id = await self.sendSMB(msg)
		
		rply = await self.recvSMB(message_id)
		print('session got reply2!')
		print(rply)
		
		fh = FileHandle.from_create_reply(rply, tree_id, file_path, oplock_level)
		self.FileHandleTable[fh.file_id] = fh
		return rply.command.FileId
	
	async def read(self, tree_id, file_id, offset = 0, length = 0):
		"""
		Will issue one read command only then waits for reply. To read a whole file you must use a filereader logic! 
		"""
		if tree_id not in self.TreeConnectTable_id:
			raise Exception('Unknown Tree ID!')
		if file_id not in self.FileHandleTable:
			raise Exception('Unknown File ID!')
			
		command = READ_REQ()
		command.Length = length
		command.Offset = offset
		command.FileId = file_id
		command.MinimumCount = 0
		command.RemainingBytes = 0
		
		header = SMB2Header_SYNC()
		header.Command  = SMB2Command.READ
		header.TreeId = tree_id
		
		msg = SMBMessage(header, command)
		message_id = await self.sendSMB(msg)
		
		rply = await self.recvSMB(message_id)
		print('session got reply2!')
		print(rply)
		
	async def query_info(self, tree_id, file_id, info_type = QueryInfoType.FILE, info_class = FileInfoClass.FileStandardInformation, additional_information = 0, flags = 0, data_in = ''):
		if tree_id not in self.TreeConnectTable_id:
			raise Exception('Unknown Tree ID!')
		if file_id not in self.FileHandleTable:
			raise Exception('Unknown File ID!')
			
		command = QUERY_INFO_REQ()
		command.InfoType = info_type
		command.FileInfoClass = info_class
		command.AdditionalInformation = additional_information
		command.Flags = flags
		command.FileId = file_id
		command.Data = data_in
		
		header = SMB2Header_SYNC()
		header.Command  = SMB2Command.QUERY_INFO
		header.TreeId = tree_id
		
		msg = SMBMessage(header, command)
		message_id = await self.sendSMB(msg)

		rply = await self.recvSMB(message_id)
		print('session got reply2!')
		print(rply)
		
	async def query_directory(self, tree_id, file_id, search_pattern = '*', resume_index = 0, information_class = FileInfoClass.FileFullDirectoryInformation, maxBufferSize = None, flags = 0):
		if tree_id not in self.TreeConnectTable_id:
			raise Exception('Unknown Tree ID!')
		if file_id not in self.FileHandleTable:
			raise Exception('Unknown File ID!')
			
		
		command = QUERY_DIRECTORY_REQ()
		command.FileInformationClass  = information_class
		command.Flags = 0
		if resume_index != 0 :
			command.Flags |= QueryDirectoryFlag.SMB2_INDEX_SPECIFIED
		command.FileIndex  = resume_index
		command.FileId  = file_id
		command.FileName = search_pattern
		
		header = SMB2Header_SYNC()
		header.Command  = SMB2Command.QUERY_DIRECTORY
		header.TreeId = tree_id
		
		msg = SMBMessage(header, command)
		message_id = await self.sendSMB(msg)

		rply = await self.recvSMB(message_id)
		print('session got reply2!')
		print(rply)
		
		if information_class == FileInfoClass.FileFullDirectoryInformation:
			return FileFullDirectoryInformationList.from_bytes(rply.command.Data)
			
		else:
			return rply.command.Data
			
		
class SMBEndpoint:
	def __init__(self):
		self.address = None		
		self.shares = {}
		self.connection = None
		
	async def list_shares(self):
		"""
		Returns a list of SMBShare objects
		"""
		raise Exception('Not implemented :(')
		
	async def connect_share(self, share):
		"""
		Connect to the share and fills connection related info in the SMBShare object
		"""
		tree_entry = await connection.tree_connect(share.fullpath)
		share.tree_id = tree_entry.tree_id
		share.maximal_access = tree_entry.maximal_access
		
		return
		
	async def list_share(self, share):
		"""
		Lists all files and folders on a share, adds the info to the share object
		
		"""
		if not share.tree_id:
			await self.connect_share(share)
		
		file_path = ''
		desired_access = FileAccessMask.FILE_READ_DATA
		share_mode = ShareAccess.FILE_SHARE_READ
		create_options = CreateOptions.FILE_DIRECTORY_FILE
		file_attrs = 0
		create_disposition = CreateDisposition.FILE_OPEN
		
		file_id = await connection.create(tree_id, file_path, desired_access, share_mode, create_options, create_disposition, file_attrs)
		info = await connection.query_directory(tree_id, file_id)
		
	async def list_directory(self, directory):
		"""
		Lists all files and folders in the directory
		directory: SMBDirectory
		fills the SMBDirectory's data
		"""
		pass
		
	def get_file(self, file, destination_path):
		"""
		Downloads the file to the given destination path
		file: SMBFile
		"""
		pass
		
	def get_file_sid(self, file):
		"""
		Gets the file's SID and fills the file object's attribute
		file: SMBFile
		"""
		pass
		
	def connect_file(self, file):
		"""
		Gets a fileID to the destination file. It is needed for SMB operations
		file: SMBFile
		"""
		pass
		
	def create_file(self, file):
		"""
		Creates a new file on the remote endpoint
		"""
		pass
		
	def write_file(self, file, offset, data):
		"""
		Writes the given data to the given offset to the file
		file: SMBFile
		offset: int
		data: io.BytesIO buffer
		"""
		pass
		
	async def test(self):
		share = SMBShare()
		share.fullpath = '\\\\10.10.10.2\\Users'
		share.name = 'self.shares'
		self.shares[share.name] = share
		
		await self.connect_share(share)
		await self.list_directory(share)
		
	

class SMBShare:
	def __init__(self):
		self.fullpath = None
		self.name = None
		self.type = None
		self.flags = None
		self.capabilities = None
		self.maximal_access = None
		
		self.files = {}
		self.subdirs = {}
		
class SMBDirectory:
	def __init__(self):
		self.parent_dir = None
		self.file_name = None
		self.creation_time = None
		self.last_access_time = None
		self.last_write_time = None
		self.change_time = None
		self.allocation_size = None
		self.attributes = None
		self.file_id = None
		self.sid = None
		
		self.files = {}
		self.subdirs = {}
		
class SMBFile:
	def __init__(self):
		self.parent_dir = None
		self.file_name = None
		self.file_size = None
		self.creation_time = None
		self.last_access_time = None
		self.last_write_time = None
		self.change_time = None
		self.allocation_size = None
		self.attributes = None
		self.file_id = None
		self.sid = None
"""
class SMBFileOps:
	def __init__(self):
		self.connection = None
		
	def list_directory(self, path, recursive = False):
	
	
	def get_file_dacl(self, path):

"""	
		
			
async def test(target):
	#setting up NTLM auth
	template_name = 'Windows10_15063_knowkey'
	credential = Credential()
	credential.username = 'victim'
	credential.password = 'Passw0rd!1'
	credential.domain = 'TEST'
	
	settings = NTLMHandlerSettings(credential, mode = 'CLIENT', template_name = template_name)
	handler = NTLMAUTHHandler(settings)
	
	#setting up SPNEGO
	spneg = SPNEGO()
	spneg.add_auth_context('NTLMSSP - Microsoft NTLM Security Support Provider', handler)
	connection = SMBConnection(spneg, [SMBDialect.SMB2_2])
	await connection.connect(target)
	await connection.negotiate()
	await connection.session_setup()
	tree_entry = await connection.tree_connect('\\\\10.10.10.2\\Users')
	tree_id = tree_entry.tree_id
	file_path = 'Administrator\\Desktop\\smb_test\\testfile1.txt'
	
	desired_access = FileAccessMask.FILE_READ_DATA
	share_mode = ShareAccess.FILE_SHARE_READ
	create_options = CreateOptions.FILE_NON_DIRECTORY_FILE
	file_attrs = 0
	create_disposition = CreateDisposition.FILE_OPEN
	
	file_id = await connection.create(tree_id, file_path, desired_access, share_mode, create_options, create_disposition, file_attrs)
	
	await connection.query_info(tree_id, file_id)
	await connection.read(tree_id, file_id, offset = 0, length = 20)
	
	tree_entry = await connection.tree_connect('\\\\10.10.10.2\\Users')
	tree_id = tree_entry.tree_id
	file_path = 'Administrator\\Desktop\\smb_test\\'
	
	desired_access = FileAccessMask.FILE_READ_DATA
	share_mode = ShareAccess.FILE_SHARE_READ
	create_options = CreateOptions.FILE_DIRECTORY_FILE
	file_attrs = 0
	create_disposition = CreateDisposition.FILE_OPEN
	
	file_id = await connection.create(tree_id, file_path, desired_access, share_mode, create_options, create_disposition, file_attrs)
	info = await connection.query_directory(tree_id, file_id)
	print(str(info))
			
if __name__ == '__main__':
	target = SMBTarget()
	target.ip = '10.10.10.2'
	target.port = 445

	asyncio.run(test(target))
	
	