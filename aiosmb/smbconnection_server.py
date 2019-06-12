import enum
import asyncio
import hmac
import hashlib
import platform
import copy

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

from aiosmb.dtyp.constrcuted_security.security_descriptor import SECURITY_DESCRIPTOR

from aiosmb.commons.smbcontainer import *
from aiosmb.commons.smbtarget import *
from aiosmb.filereader import SMBFileReader



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
	def __init__(self, gssapi, netbios_transport, dialects = [NegotiateDialects.SMB202], shutdown_evt = asyncio.Event()):
		self.gssapi = gssapi
		self.original_gssapi = copy.deepcopy(gssapi) #preserving a copy of the original
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
			msg = await self.recv_smb()
			print(msg)
		
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
			#print('Waiting on messageID : %s' % message_id)
			await self.OutstandingResponsesEvent[message_id].wait()
		
		msg = self.OutstandingResponses.pop(message_id)
		
		if msg.header.Status != NTStatus.PENDING:
			if message_id in self.OutstandingResponsesEvent:
				del self.OutstandingResponsesEvent[message_id]
		else:
			self.OutstandingResponsesEvent[message_id].clear()
		
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
		Initiates protocol negotiation.
		First we send an SMB_COM_NEGOTIATE_REQ with our supported dialects
		"""
		
		#let's construct an SMBv1 SMB_COM_NEGOTIATE_REQ packet
		header = SMBHeader()
		header.Command  = SMBCommand.SMB_COM_NEGOTIATE
		header.Status   = NTStatus.SUCCESS
		header.Flags    = 0
		header.Flags2   = SMBHeaderFlags2Enum.SMB_FLAGS2_UNICODE
			
		command = SMB_COM_NEGOTIATE_REQ()				
		command.Dialects = ['SMB 2.???']
		
		msg = SMBMessage(header, command)
		message_id = await self.sendSMB(msg)
		
		#recieveing reply, should be version2, because currently we dont support v1 :(
		rply = await self.recvSMB(message_id) #negotiate MessageId should be 1
		
		if rply.header.Status == NTStatus.SUCCESS:
			if isinstance(rply, SMB2Message):
				
				if rply.command.DialectRevision == NegotiateDialects.WILDCARD:
					command = NEGOTIATE_REQ()
					command.SecurityMode    = NegotiateSecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED | NegotiateSecurityMode.SMB2_NEGOTIATE_SIGNING_REQUIRED
					command.Capabilities    = 0
					command.ClientGuid      = self.ClientGUID
					command.Dialects        = self.dialects
						
					header = SMB2Header_SYNC()
					header.Command  = SMB2Command.NEGOTIATE
					header.CreditReq = 0
					
					msg = SMB2Message(header, command)
					message_id = await self.sendSMB(msg)
					rply = await self.recvSMB(message_id) #negotiate MessageId should be 1
					if rply.header.Status != NTStatus.SUCCESS:
						print('session got reply!')
						print(rply)
						raise Exception('session_setup_1 (authentication probably failed) reply: %s' % rply.header.Status)
					
				if rply.command.DialectRevision not in self.supported_dialects:
					raise SMBUnsupportedDialectSelected()
				
				self.selected_dialect = rply.command.DialectRevision
				self.signing_required = NegotiateSecurityMode.SMB2_NEGOTIATE_SIGNING_REQUIRED in rply.command.SecurityMode
				logger.log(1, 'Server selected dialect: %s' % self.selected_dialect)
				
				self.MaxTransactSize = min(0x100000, rply.command.MaxTransactSize)
				self.MaxReadSize = min(0x100000, rply.command.MaxReadSize)
				self.MaxWriteSize = min(0x100000, rply.command.MaxWriteSize)
				self.ServerGuid = rply.command.ServerGuid
				self.SupportsMultiChannel = NegotiateCapabilities.MULTI_CHANNEL in rply.command.Capabilities
				
			else:
				logger.error('Server choose SMB v1 which is not supported currently')
				raise SMBUnsupportedSMBVersion()
			
		else:
			print('session got reply!')
			print(rply)
			raise Exception('session_setup_1 (authentication probably failed) reply: %s' % rply.header.Status)
			
			
			
		self.status = SMBConnectionStatus.SESSIONSETUP
		


		
		
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
		if self.status == SMBConnectionStatus.NEGOTIATING:
			if isinstance(msg, SMBMessage):
				#creating an event for outstanding response
				self.OutstandingResponsesEvent[0] = asyncio.Event()
				await self.netbios_transport.out_queue.put(msg)
				self.SequenceWindow += 1
				return 0
			else:
				msg.header.CreditCharge = 1
				msg.header.CreditReq = 127
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
		
		#creating an event for outstanding response
		self.OutstandingResponsesEvent[message_id] = asyncio.Event()
		
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
	
	