import enum
import asyncio
import hmac
import hashlib
import platform
import copy
import datetime

from aiosmb import logger
from aiosmb.exceptions import *
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
from aiosmb.protocol.common import *
from aiosmb.dtyp.constrcuted_security.guid import *
from aiosmb.commons.access_mask import *
from aiosmb.fscc.structures.fileinfoclass import *
from aiosmb.fscc.structures.FileFullDirectoryInformation import *
from aiosmb.fscc.FileAttributes import FileAttributes

from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR

from aiosmb.commons.smbcontainer import *
from aiosmb.commons.smbtarget import *



class SMBConnectionStatus(enum.Enum):
	NEGOTIATING = 'NEGOTIATING'
	SESSIONSETUP = 'SESSIONSETUP'
	RUNNING = 'RUNNING'
	CLOSED = 'CLOSED'
	
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

class SMBServerConnection:
	"""
	Connection class for network connectivity and SMB messages management (sending/recieveing/singing/encrypting).
	"""
	def __init__(self, server_settings, netbios_transport, dialects = [NegotiateDialects.SMB202], shutdown_evt = asyncio.Event()):
		self.settings = server_settings
		self.client_gssapi = self.settings.client_gssapi
		self.original_client_gssapi = copy.deepcopy(self.client_gssapi) #preserving a copy of the original
		self.shutdown_evt = shutdown_evt
		
		#######DONT CHANGE THIS
		self.supported_dialects = [NegotiateDialects.WILDCARD, NegotiateDialects.SMB202, NegotiateDialects.SMB210]
		#######
		
		self.settings = None
		self.network_transport = None 
		self.netbios_transport = netbios_transport
		self.dialects = dialects #list of SMBDialect
		
		self.selected_dialect = None
		self.signing_required = False
		self.encryption_required = False
		
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
		self.ServerGuid = GUID.random()
		self.RequireSigning = False
		self.ServerName = None
		self.ClientGUID = None
		
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
		
		
	async def __aenter__(self):
		return self
		
	async def __aexit__(self, exc_type, exc, traceback):
		await self.terminate()
		
	async def main(self):
		logger.info('SMB Server starting')
		logger.info('SMB Server creating NB transport reader task')
		asyncio.ensure_future(self.__handle_smb_in())
		
		logger.info('SMB Server running')
		while True:
			if self.status == SMBConnectionStatus.NEGOTIATING:
				await self.negotiate()
			if self.status == SMBConnectionStatus.SESSIONSETUP:
				await self.session_setup()
			else:
				raise Exception('Not implemented!')
		
	async def __handle_smb_in(self):
		"""
		Waits from SMB messages from the NetBIOSTransport in_queue, and fills the connection table.
		This function started automatically when calling connect.
		"""
		while not self.shutdown_evt.is_set():
			msg = await self.netbios_transport.in_queue.get()
			
			logger.log(1, '__handle_smb_in got new message with Id %s' % msg.header.MessageId)
			
			if isinstance(msg, SMB2Transform):
				#message is encrypted
				#this point we should decrypt it and only store the decrypted part in the OutstandingResponses table
				#but for now we just thropw exception bc encryption is not implemented
				raise Exception('Encrypted SMBv2 message recieved, but encryption is not yet supported!')
			
			self.OutstandingResponses[msg.header.MessageId] = msg
			if msg.header.MessageId in self.OutstandingResponsesEvent:
				self.OutstandingResponsesEvent[msg.header.MessageId].set()
			else:
				#here we are loosing messages, the functionality for "PENDING" and "SHARING_VIOLATION" should be written
				continue
		
		
	async def recvSMB(self, message_id):
		"""
		Returns an SMB message from the outstandingresponse dict, OR waits until the expected message_id appears.
		"""
		if message_id not in self.OutstandingResponses:
			self.OutstandingResponsesEvent[message_id] = asyncio.Event()
			await self.OutstandingResponsesEvent[message_id].wait()
		
		msg = self.OutstandingResponses.pop(message_id)
		
		return msg
	
		
	async def disconnect(self):
		"""
		Teras down the socket connecting as well as the reading cycle.
		Doesn't do any cleanup! 
		For proper cleanup call the terminate function.
		"""
		if self.status == SMBConnectionStatus.CLOSED:
			return
		
		self.status = SMBConnectionStatus.CLOSED
		self.shutdown_evt.set()
		await self.netbios_transport.stop()
		
		
		
	async def negotiate(self):
		"""
		"""

		rply = await self.recvSMB(0)

		#TODO: check if SMB2 is supported
		#currently we just continue with SMB2

		command = NEGOTIATE_REPLY()
		command.SecurityMode = NegotiateSecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED
		command.DialectRevision = NegotiateDialects.WILDCARD
		command.NegotiateContextCount = 0
		command.ServerGuid = self.ServerGuid
		command.Capabilities = 0
		command.SystemTime = datetime.datetime.now()
		command.ServerStartTime = datetime.datetime.now() - datetime.timedelta(days=1)
		command.Buffer = self.client_gssapi.get_mechtypes_list()

			
		header = SMB2Header_SYNC()
		header.Command  = SMB2Command.NEGOTIATE
		header.CreditReq = 0
		
		msg = SMBMessage(header, command)
		message_id = await self.sendSMB(msg)
		print(message_id)
		rply = await self.recvSMB(1)
		#recieveing reply, should be version2, because currently we dont support v1 :(
		 #negotiate MessageId should be 1
		
		print('1111111111111111111111111')

		#TODO: check if SMB2 is supported
		#currently we just continue with SMB2

		command = NEGOTIATE_REPLY()
		command.SecurityMode = NegotiateSecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED
		command.DialectRevision = NegotiateDialects.SMB202
		command.NegotiateContextCount = 0
		command.ServerGuid = self.ServerGuid
		command.Capabilities = 0
		command.SystemTime = datetime.datetime.now()
		command.ServerStartTime = datetime.datetime.now() - datetime.timedelta(days=1)
		command.Buffer = self.client_gssapi.get_mechtypes_list()

			
		header = SMB2Header_SYNC()
		header.Command  = SMB2Command.NEGOTIATE
		header.CreditReq = 0
		
		msg = SMBMessage(header, command)
		message_id = await self.sendSMB(msg)
		
		self.status = SMBConnectionStatus.SESSIONSETUP
		return

	async def session_setup(self):
		print('session_setup')
		rply = await self.recvSMB(2)
		self.SessionId = int.from_bytes(os.urandom(8), 'big', signed = False)
		auth_data = rply.command.Buffer
		print('clinet buffer: %s' % auth_data)
		data, res, err = await self.client_gssapi.authenticate(auth_data)
		if err is not None:
			raise err

		command = SESSION_SETUP_REPLY()
		command.SessionFlags = 0
		command.Buffer = data

			
		header = SMB2Header_SYNC()
		header.Command  = SMB2Command.SESSION_SETUP
		header.CreditReq = 127
		header.Status = NTStatus.MORE_PROCESSING_REQUIRED
		
		msg = SMBMessage(header, command)
		message_id = await self.sendSMB(msg)
		print(message_id)
		rply = await self.recvSMB(3)


		
		
	def sign_message(self, msg):
		if self.selected_dialect in [NegotiateDialects.SMB202, NegotiateDialects.SMB210]:
			if self.SessionKey:
				msg.header.Flags = msg.header.Flags ^ SMB2HeaderFlag.SMB2_FLAGS_SIGNED ##maybe move this flag settings to sendsmb since singing is determined there?
				digest = hmac.new(self.SessionKey, msg.to_bytes(), hashlib.sha256).digest()
				msg.header.Signature = digest[:16]
		else:
			raise SMBUnsupportedDialectSign()
		
		
	async def sendSMB(self, msg):
		"""
		Sends an SMB message to teh remote endpoint.
		msg: SMB2Message or SMBMessage
		Returns: MessageId integer
		"""
		msg.header.Flags |= SMB2HeaderFlag.SMB2_FLAGS_SERVER_TO_REDIR
		if self.status == SMBConnectionStatus.NEGOTIATING:
			msg.header.CreditCharge = 1
			msg.header.CreditReq = 1
			msg.header.MessageId = self.SequenceWindow
			message_id = self.SequenceWindow
			self.SequenceWindow += 1
			
			self.OutstandingResponsesEvent[message_id] = asyncio.Event()
			await self.netbios_transport.out_queue.put(msg)
			return message_id
				

		if msg.header.Command is not SMB2Command.CANCEL:
			msg.header.MessageId = self.SequenceWindow
			self.SequenceWindow += 1
		
		msg.header.SessionId = self.SessionId
		
		if not msg.header.CreditCharge:
			msg.header.CreditCharge = 1
		
		if self.status != SMBConnectionStatus.SESSIONSETUP:
			msg.header.CreditReq = 127
		
		message_id = msg.header.MessageId
		
		if self.signing_required == True:
			self.sign_message(msg)
		
		if self.encryption_required == True:
			raise Exception('SMB Encryption not implemented yet :(')
			#self.encrypt_message(msg)
		
		###creating an event for outstanding response
		###self.OutstandingResponsesEvent[message_id] = asyncio.Event()

		if msg.header.Status != NTStatus.PENDING:
			if message_id in self.OutstandingResponsesEvent:
				del self.OutstandingResponsesEvent[message_id]
		else:
			self.OutstandingResponsesEvent[message_id].clear()
		
		await self.netbios_transport.out_queue.put(msg)
		
		return message_id
	
	
	
			
if __name__ == '__main__':
	target = SMBTarget()
	target.ip = '10.10.10.2'
	target.port = 445
	
	target_bad = SMBTarget()
	target_bad.ip = '10.10.10.66'
	target_bad.port = 445

	#asyncio.run(test(target))
	#asyncio.run(test_kerberos(target))
	#asyncio.run(test_sspi_kerberos(target))
	#asyncio.run(test_sspi_ntlm(target))
	#asyncio.run(connection_test(target))
	#asyncio.run(test_high(target))
	asyncio.run(filereader_test(target))
	
	