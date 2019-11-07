import enum
import asyncio
import hmac
import hashlib
import platform
import copy
import traceback
import datetime

from aiosmb import logger
from aiosmb.commons.exceptions import *
from aiosmb.network.selector import NetworkSelector
from aiosmb.transport.netbios import NetBIOSTransport
from aiosmb.protocol.smb.command_codes import SMBCommand
from aiosmb.wintypes.ntstatus import NTStatus
from aiosmb.protocol.smb.header import SMBHeader, SMBHeaderFlags2Enum
from aiosmb.protocol.smb.message import SMBMessage
from aiosmb.protocol.smb.commands import *
from aiosmb.protocol.smb2.message import SMB2Message, SMB2Transform
from aiosmb.protocol.smb2.commands import *
from aiosmb.protocol.smb2.headers import *
from aiosmb.protocol.smb2.command_codes import *
from aiosmb.protocol.common import *
from aiosmb.wintypes.dtyp.constrcuted_security.guid import *
from aiosmb.wintypes.access_mask import *
from aiosmb.wintypes.fscc.structures.fileinfoclass import *
from aiosmb.wintypes.fscc.structures.FileFullDirectoryInformation import *
from aiosmb.wintypes.fscc.FileAttributes import FileAttributes

from aiosmb.wintypes.dtyp.constrcuted_security.security_descriptor import SECURITY_DESCRIPTOR

from aiosmb.commons.smbcontainer import *
from aiosmb.commons.connection.target import *



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

class SMBPendingMsg:
	def __init__(self, message_id, OutstandingResponses, OutstandingResponsesEvent, timeout = 5, max_renewal = None):
		self.message_id = message_id
		self.max_renewal = max_renewal
		self.timeout = timeout #different operations require different timeouts, even depending on dielacts!!!
		self.OutstandingResponses = OutstandingResponses
		self.OutstandingResponsesEvent = OutstandingResponsesEvent
		self.pending_task = None

	async def __pending_waiter(self):
		await asyncio.sleep(self.timeout)
		await self.__destroy_message(SMBPendingTimeout())

	async def __destroy_message(self, problem):
		self.OutstandingResponses[self.message_id] = problem
		if self.message_id in self.OutstandingResponsesEvent:
			self.OutstandingResponsesEvent[self.message_id].set()
		return

	async def update(self):
		if self.pending_task is not None:
			self.pending_task.cancel()
		
		if self.max_renewal is not None:
			self.max_renewal -= 1
			if self.max_renewal == 0:
				await self.__destroy_message(SMBPendingMaxRenewal())
		self.pending_task = asyncio.create_task(self.__pending_waiter())


	async def run(self):
		self.pending_task = asyncio.create_task(self.__pending_waiter())

	async def stop(self):
		if self.pending_task is not None:
			self.pending_task.cancel()

class SMBConnection:
	"""
	Connection class for network connectivity and SMB messages management (sending/recieveing/singing/encrypting).
	"""
	def __init__(self, gssapi, target, dialects = [NegotiateDialects.SMB202], shutdown_evt = asyncio.Event()):
		self.gssapi = gssapi
		self.original_gssapi = copy.deepcopy(gssapi) #preserving a copy of the original
		self.shutdown_evt = shutdown_evt
		
		self.target = target
		
		#######DONT CHANGE THIS
		self.supported_dialects = [NegotiateDialects.WILDCARD, NegotiateDialects.SMB202, NegotiateDialects.SMB210]
		#self.supported_dialects = [NegotiateDialects.SMB202, NegotiateDialects.SMB210]
		#######
		
		self.settings = None
		self.network_transport = None 
		self.netbios_transport = None #this class is used by the netbios transport class, keeping it here also maybe you like to go in raw
		self.incoming_task = None
		self.keepalive_task = None
		self.activity_at = None
		self.dialects = dialects #list of SMBDialect
		
		self.selected_dialect = None
		self.signing_required = False
		self.encryption_required = False
		
		self.status = SMBConnectionStatus.NEGOTIATING
		
		self.OutstandingResponsesEvent = {}
		self.OutstandingRequests = {}
		self.OutstandingResponses = {}

		self.pending_table = {}
		
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
		
		#ignore_close is there to skip the logoff/closing of the channel
		#this is useful because there could be certain errors after a scusessful logon
		#that invalidates the whole session (eg. STATUS_USER_SESSION_DELETED)
		#if this happens then logoff will fail as well!
		self.session_closed = False 
		
	async def __aenter__(self):
		return self
		
	async def __aexit__(self, exc_type, exc, traceback):
		await asyncio.wait_for(self.terminate(), timeout = 1)

	def get_extra_info(self):
		return self.gssapi.get_extra_info()

	async def __pending_task(self, message_id, timeout = 5):
		await asyncio.sleep(timeout)
		

	async def __handle_smb_in(self):
		"""
		Waits from SMB messages from the NetBIOSTransport in_queue, and fills the connection table.
		This function started automatically when calling connect.
		"""
		try:
			while not self.shutdown_evt.is_set():
				msg, err = await self.netbios_transport.in_queue.get()
				self.activity_at = datetime.datetime.utcnow()
				if err is not None:
					logger.error('__handle_smb_in got error from transport layer %s' % err)
					#setting all outstanding events to finished
					for mid in self.OutstandingResponsesEvent:
						self.OutstandingResponses[mid] = None
						self.OutstandingResponsesEvent[mid].set()

					await self.terminate()
					return

				logger.log(1, '__handle_smb_in got new message with Id %s' % msg.header.MessageId)
				
				if isinstance(msg, SMB2Transform):
					#message is encrypted
					#this point we should decrypt it and only store the decrypted part in the OutstandingResponses table
					#but for now we just thropw exception bc encryption is not implemented
					raise Exception('Encrypted SMBv2 message recieved, but encryption is not yet supported!')
				
				if msg.header.Status == NTStatus.PENDING:
					self.pending_table[msg.header.MessageId] = SMBPendingMsg(msg.header.MessageId, self.OutstandingResponses, self.OutstandingResponsesEvent)
					await self.pending_table[msg.header.MessageId].run()
					continue

				if msg.header.MessageId in self.pending_table:
					await self.pending_table[msg.header.MessageId].stop()
					del self.pending_table[msg.header.MessageId]

				self.OutstandingResponses[msg.header.MessageId] = msg
				if msg.header.MessageId in self.OutstandingResponsesEvent:
					self.OutstandingResponsesEvent[msg.header.MessageId].set()
				else:

					#here we are loosing messages, the functionality for "PENDING" and "SHARING_VIOLATION" should be implemented
					continue
		except asyncio.CancelledError:
			#the SMB connection is terminating
			return
		except:
			logger.exception('__handle_smb_in')
			
			
	async def login(self):
		"""
		This is the normal starting function.
		Performs establishment of the TCP connection, then the negotiation and finally the session setup.
		If this function returns without an exception, then I'm happy.
		Also it means that you have a working and active session to the server.
		"""
		results = await asyncio.gather(*[self.connect()], return_exceptions=True)
		if isinstance(results[0], Exception):
			raise results[0]
		await self.negotiate()
		await self.session_setup()
		self.keepalive_task = asyncio.create_task(self.keepalive())
		
	async def fake_login(self):
		if 'NTLMSSP - Microsoft NTLM Security Support Provider' not in self.gssapi.authentication_contexts:
			raise Exception('Fake authentication is only supported via NTLM package')
		await self.connect()
		await self.negotiate()
		await self.session_setup(fake_auth = True)
		await self.disconnect()
		return self.gssapi.get_extra_info()
		
	async def connect(self):
		"""
		Establishes socket connection to the remote endpoint. Also starts the internal reading procedures.
		"""
		self.network_transport = await NetworkSelector.select(self.target)
		
		res = await asyncio.gather(*[self.network_transport.connect()], return_exceptions=True)
		if isinstance(res[0], Exception):
			raise res[0]
		
		
		self.netbios_transport = NetBIOSTransport(self.network_transport)
		res =  await asyncio.gather(*[self.netbios_transport.run()], return_exceptions=True)
		if isinstance(res[0], Exception):
			raise res[0]
		
		self.incoming_task = asyncio.create_task(self.__handle_smb_in())
		
	async def disconnect(self):
		"""
		Tears down the socket connecting as well as the reading cycle.
		Doesn't do any cleanup! 
		For proper cleanup call the terminate function.
		"""
		if self.status == SMBConnectionStatus.CLOSED:
			return
		
		self.status = SMBConnectionStatus.CLOSED
		if self.netbios_transport:
			await self.netbios_transport.stop()
		if self.network_transport:
			await self.network_transport.disconnect()
		if self.incoming_task:
			self.incoming_task.cancel()
		
		if self.keepalive_task:
			self.keepalive_task.cancel()

	async def keepalive(self):
		"""
		Sends an echo message every X seconds to the server to keep the channel open
		"""
		try:
			sleep_time = 10
			if self.target.timeout < 0:
				return
			elif self.target.timeout > 0:
				sleep_time = max(self.target.timeout - 1, sleep_time)
			while True:
				await asyncio.sleep(sleep_time)
				if (datetime.datetime.utcnow() - self.activity_at).seconds > sleep_time: 
					await self.echo()
				
		except asyncio.CancelledError:
			return
		except Exception as e:
			logger.error('Keepalive failed! Server probably disconnected!')
			await self.disconnect()


		
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
				self.signing_required = NegotiateSecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED in rply.command.SecurityMode
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
		
	async def session_setup(self, fake_auth = False):
		
		authdata = None
		status = NTStatus.MORE_PROCESSING_REQUIRED
		maxiter = 5
		while status == NTStatus.MORE_PROCESSING_REQUIRED and maxiter > 0:
			command = SESSION_SETUP_REQ()
			try:
				command.Buffer, res  = await self.gssapi.authenticate(authdata)
				if fake_auth == True:
					if self.gssapi.selected_authentication_context is not None and self.gssapi.selected_authentication_context.ntlmChallenge is not None:
						return
			except Exception as e:
				logger.exception('GSSAPI auth failed!')
				#TODO: Clear this up, kerberos lib needs it's own exceptions!
				if str(e).find('Preauth') != -1:
					raise SMBKerberosPreauthFailed()
				else:
					raise e
					#raise SMBKerberosPreauthFailed()
			
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
			
			if self.SessionId == 0:
				self.SessionId = rply.header.SessionId
			
			if rply.header.Status not in [NTStatus.SUCCESS, NTStatus.MORE_PROCESSING_REQUIRED]:
				break
			
			authdata = rply.command.Buffer
			status = rply.header.Status
			maxiter -= 1
		
		if rply.header.Status == NTStatus.SUCCESS:
			self.SessionKey = self.gssapi.get_session_key()[:16]
			
			# TODO: key calc
			if self.signing_required and self.selected_dialect in [NegotiateDialects.SMB300 , NegotiateDialects.SMB302 , NegotiateDialects.SMB311]:
				self.SigningKey      = crypto.KDF_CounterMode(self.SessionKey, b"SMB2AESCMAC\x00", "SmbSign\x00", 128)
				self.ApplicationKey  = crypto.KDF_CounterMode(self.SessionKey, b"SMB2APP\x00", "SmbRpc\x00", 128)
				self.EncryptionKey   = crypto.KDF_CounterMode(self.SessionKey, b"SMB2AESCCM\x00", "ServerIn \x00", 128)
				self.DecryptionKey   = crypto.KDF_CounterMode(self.SessionKey, b"SMB2AESCCM\x00", "ServerOut\x00", 128)
			
			self.status = SMBConnectionStatus.RUNNING
		
		elif rply.header.Status == NTStatus.LOGON_FAILURE:
			raise SMBAuthenticationFailed()
		
		else:
			raise SMBException('session_setup (authentication probably failed)', rply.header.Status)
			
		
		
	async def recvSMB(self, message_id):
		"""
		Returns an SMB message from the outstandingresponse dict, OR waits until the expected message_id appears.
		"""
		if message_id not in self.OutstandingResponses:
			logger.log(1, 'Waiting on messageID : %s' % message_id)
			await self.OutstandingResponsesEvent[message_id].wait()
			
		msg = self.OutstandingResponses.pop(message_id)
		
		if msg.header.Status != NTStatus.PENDING:
			if message_id in self.OutstandingResponsesEvent:
				del self.OutstandingResponsesEvent[message_id]
		else:
			self.OutstandingResponsesEvent[message_id].clear()
		
		return msg
		
		
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
		self.activity_at = datetime.datetime.utcnow()
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
		
	async def tree_connect(self, share_name):
		"""
		share_name MUST be in "\\\\server\\share" format! Server can be NetBIOS name OR IP4 OR IP6 OR FQDN
		"""
		if self.session_closed == True:
			return
		command = TREE_CONNECT_REQ()
		command.Path = share_name
		command.Flags = 0
		
		header = SMB2Header_SYNC()
		header.Command  = SMB2Command.TREE_CONNECT
		
		msg = SMBMessage(header, command)
		message_id = await self.sendSMB(msg)
		
		rply = await self.recvSMB(message_id)
		
		if rply.header.Status == NTStatus.SUCCESS:
			te = TreeEntry.from_tree_reply(rply, share_name)
			self.TreeConnectTable_id[rply.header.TreeId] = te
			self.TreeConnectTable_share[share_name] = te
			return te
		
		elif rply.header.Status == NTStatus.BAD_NETWORK_NAME:
			raise SMBIncorrectShareName()
			
		elif rply.header.Status == NTStatus.USER_SESSION_DELETED:
			self.session_closed = True
			raise SMBException('session delted', NTStatus.USER_SESSION_DELETED)
		
		
		else:
			raise SMBException('', rply.header.Status)
		
	async def create(self, tree_id, file_path, desired_access, share_mode, create_options, create_disposition, file_attrs, impresonation_level = ImpersonationLevel.Impersonation, oplock_level = OplockLevel.SMB2_OPLOCK_LEVEL_NONE, create_contexts = None, return_reply = False):
		if self.session_closed == True:
			return
		
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
		
		if rply.header.Status == NTStatus.SUCCESS:
			fh = FileHandle.from_create_reply(rply, tree_id, file_path, oplock_level)
			self.FileHandleTable[fh.file_id] = fh
			
			if return_reply == True:
				return rply.command.FileId, rply.command
			return rply.command.FileId
		
		elif rply.header.Status == NTStatus.ACCESS_DENIED:
			#this could mean incorrect filename/foldername OR actually access denied
			raise SMBCreateAccessDenied()
			
		else:
			raise SMBException('', rply.header.Status)
	
	async def read(self, tree_id, file_id, offset = 0, length = 0):
		"""
		Will issue one read command only then waits for reply. To read a whole file you must use a filereader logic! 
		returns the data bytes and the remaining data length
		
		IMPORTANT: remaning data length is dependent on the length of the requested chunk (length param) not on the actual file length.
		to get the remaining length for the actual file you must set the length parameter to the correct file size!
		
		If and EOF happens the function returns an empty byte array and the remaining data is set to 0
		"""
		if self.session_closed == True:
			return
			
		if tree_id not in self.TreeConnectTable_id:
			raise Exception('Unknown Tree ID!')
		if file_id not in self.FileHandleTable:
			raise Exception('Unknown File ID!')
			
		header = SMB2Header_SYNC()
		header.Command  = SMB2Command.READ
		header.TreeId = tree_id
		
		if length < self.MaxReadSize:
			length = self.MaxReadSize
		
		if self.selected_dialect != NegotiateDialects.SMB202 and self.SupportsMultiCredit == True:
			header.CreditCharge = ( 1 + (length - 1) // 65536)
		else: 
			length = min(65536,length)
			
		command = READ_REQ()
		command.Length = length
		command.Offset = offset
		command.FileId = file_id
		command.MinimumCount = 0
		command.RemainingBytes = 0
		
		msg = SMBMessage(header, command)
		message_id = await self.sendSMB(msg)
		
		rply = await self.recvSMB(message_id)
		
		if rply.header.Status == NTStatus.SUCCESS:
			return rply.command.Buffer, rply.command.DataRemaining
		
		elif rply.header.Status == NTStatus.END_OF_FILE:
			return b'', 0
			
		else:
			raise SMBException('', rply.header.Status)
			
			
	async def write(self, tree_id, file_id, data, offset = 0):
		"""
		This function will send one packet only! The data size can be larger than what one packet allows, but it will be truncated
		to the maximum. 
		Also, there is no guarantee that the actual sent data will be fully written to the remote file! This will be indicated in the returned value.
		Use a high-level function to get a full write.
		
		"""
		if self.session_closed == True:
			return
			
		if tree_id not in self.TreeConnectTable_id:
			raise Exception('Unknown Tree ID!')
		if file_id not in self.FileHandleTable:
			raise Exception('Unknown File ID!')
			
		header = SMB2Header_SYNC()
		header.Command  = SMB2Command.WRITE
		header.TreeId = tree_id
			
		if len(data) > self.MaxWriteSize:
			data = data[:self.MaxWriteSize]
			
		if self.selected_dialect != NegotiateDialects.SMB202 and self.SupportsMultiCredit == True:
			header.CreditCharge = ( 1 + (len(data) - 1) // 65536)
		else: 
			data = data[:min(65536,len(data))]
		
		command = WRITE_REQ()
		command.Length = len(data)
		command.Offset = offset
		command.FileId = file_id
		command.Data = data
		
		msg = SMBMessage(header, command)
		message_id = await self.sendSMB(msg)
		
		rply = await self.recvSMB(message_id)
		
		if rply.header.Status == NTStatus.SUCCESS:
			return rply.command.Count
		
		else:
			SMBException('', rply.header.Status)
		
	async def query_info(self, tree_id, file_id, info_type = QueryInfoType.FILE, information_class = FileInfoClass.FileStandardInformation, additional_information = 0, flags = 0, data_in = ''):
		"""
		Queires the file or directory for specific information. The information returned is depending on the input parameters, check the documentation on msdn for a better understanding.
		The resturned data can by raw bytes or an actual object, depending on wther your info is implemented in the library.
		Sorry there are a TON of classes to deal with :(
		
		IMPORTANT: in case you are requesting big amounts of data, the result will arrive in chunks. You will need to invoke this function until None is returned to get the full data!!!
		"""
		if self.session_closed == True:
			return
		if tree_id not in self.TreeConnectTable_id:
			raise Exception('Unknown Tree ID!')
		if file_id not in self.FileHandleTable:
			raise Exception('Unknown File ID!')
			
		command = QUERY_INFO_REQ()
		command.InfoType = info_type
		command.FileInfoClass = information_class
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
		
		if rply.header.Status == NTStatus.SUCCESS:
			#https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/3b1b3598-a898-44ca-bfac-2dcae065247f
			if info_type == QueryInfoType.SECURITY:
				return SECURITY_DESCRIPTOR.from_bytes(rply.command.Data)
				
			elif info_type == QueryInfoType.FILE:
				if information_class == FileInfoClass.FileFullDirectoryInformation:
					return FileFullDirectoryInformationList.from_bytes(rply.command.Data)
					
				else:
					return rply.command.Data
					
			elif info_type == QueryInfoType.FILESYSTEM:
				#TODO: implement this
				return rply.command.Data
				
			elif info_type == QueryInfoType.QUOTA:
				#TODO: implement this
				return rply.command.Data
			
			else:
				#this should never happen
				return rply.command.Data
			
		else:
			raise SMBException('', rply.header.Status)
			
		
	async def query_directory(self, tree_id, file_id, search_pattern = '*', resume_index = 0, information_class = FileInfoClass.FileFullDirectoryInformation, maxBufferSize = None, flags = 0):
		"""
		
		IMPORTANT: in case you are requesting big amounts of data, the result will arrive in chunks. You will need to invoke this function until None is returned to get the full data!!!
		"""
		if self.session_closed == True:
			return
			
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
		
		msg = SMB2Message(header, command)
		message_id = await self.sendSMB(msg)

		rply = await self.recvSMB(message_id)
		
		if rply.header.Status == NTStatus.SUCCESS:
			if information_class == FileInfoClass.FileFullDirectoryInformation:
				return FileFullDirectoryInformationList.from_bytes(rply.command.Data)
				
			else:
				return rply.command.Data
				
		elif rply.header.Status == NTStatus.NO_MORE_FILES:
			return None
		else:
			raise Exception('query_directory reply: %s' % rply.header.Status)
			
	async def close(self, tree_id, file_id, flags = CloseFlag.NONE):
		"""
		Closes the file/directory/pipe/whatever based on file_id. It will automatically remove all traces of the file handle.
		"""
		if self.session_closed == True:
			return
		command = CLOSE_REQ()
		command.Flags = flags
		command.FileId = file_id
		
		header = SMB2Header_SYNC()
		header.Command  = SMB2Command.CLOSE
		header.TreeId = tree_id
		msg = SMB2Message(header, command)
		message_id = await self.sendSMB(msg)
		

		rply = await self.recvSMB(message_id)
		if rply.header.Status == NTStatus.SUCCESS:
			del self.FileHandleTable[file_id]
			
			
	async def flush(self, tree_id, file_id):
		"""
		Flushes all cached data that may be on the server for the given file.
		"""
		if self.session_closed == True:
			return
			
		command = FLUSH_REQ()
		command.FileId = file_id
		
		header = SMB2Header_SYNC()
		header.Command  = SMB2Command.FLUSH
		header.TreeId = tree_id
		msg = SMB2Message(header, command)
		message_id = await self.sendSMB(msg)

		rply = await self.recvSMB(message_id)
		
	async def logoff(self):
		"""
		Logs off from the server, effectively terminates the session. 
		The underlying connection will still be active, so please either clean it up manually or dont touch this function
		For proper closing of the connection use the terminate function
		"""
		if self.session_closed == True:
			return
			
		if self.status == SMBConnectionStatus.CLOSED:
			return
			
		command = LOGOFF_REQ()
		
		header = SMB2Header_SYNC()
		header.Command  = SMB2Command.LOGOFF
		msg = SMB2Message(header, command)
		message_id = await self.sendSMB(msg)

		rply = await self.recvSMB(message_id)
	
	async def echo(self):
		"""
		Issues an ECHO request to the server. Server will reply with and ECHO response, if it's still alive
		"""
		if self.session_closed == True:
			return
		command = ECHO_REQ()
		header = SMB2Header_SYNC()
		header.Command  = SMB2Command.ECHO
		msg = SMB2Message(header, command)
		message_id = await self.sendSMB(msg)
		rply = await self.recvSMB(message_id)
		
	async def tree_disconnect(self, tree_id):
		"""
		Disconnects from tree, removes all file entries associated to the tree
		"""
		if self.session_closed == True:
			return
			
		command = TREE_DISCONNECT_REQ()
		
		header = SMB2Header_SYNC()
		header.Command  = SMB2Command.TREE_DISCONNECT
		header.TreeId = tree_id
		msg = SMB2Message(header, command)
		message_id = await self.sendSMB(msg)

		rply = await self.recvSMB(message_id)
		
		if rply.header.Status == NTStatus.SUCCESS:
			del_file_ids = []
			share_name = self.TreeConnectTable_id[tree_id].share_name
			for fe in self.FileHandleTable:
				if self.FileHandleTable[fe].tree_id == tree_id:
					del_file_ids.append(self.FileHandleTable[fe].file_id)
			
			for file_id in del_file_ids:
				del self.FileHandleTable[file_id]
			
			del self.TreeConnectTable_id[tree_id]
			del self.TreeConnectTable_share[share_name]

		
	async def cancel(self, message_id):
		"""
		Issues a CANCEL command for the given message_id
		"""
		if self.session_closed == True:
			return
			
		command = CANCEL_REQ()
		header = SMB2Header_SYNC()
		header.Command  = SMB2Command.CANCEL
		msg = SMB2Message(header, command)
		msg.header.MessageId = message_id
		message_id = await self.sendSMB(msg)
		rply = await self.recvSMB(message_id)
		
	async def terminate(self):
		"""
		Use this function to properly terminate the SBM connection.
		Terminates the connection. Closes all tree handles, logs off and disconnects the TCP connection.
		"""
		#return
		try:
			logger.debug('Terminate called!')			
			if self.session_closed == True or self.status == SMBConnectionStatus.CLOSED:
				logger.debug('Terminate 1!')
				return
			
			if self.status == SMBConnectionStatus.RUNNING:
				logger.debug('Terminate 2!')
				#only doing the proper disconnection if the connection was already running
				for tree_id in list(self.TreeConnectTable_id.keys()):
					try:
						await asyncio.wait_for(self.tree_diconnect(tree_id), timeout = self.target.timeout)
					except:
						pass
				logger.debug('Terminate 3!')
				#logging off
				try:
					await asyncio.wait_for(self.logoff(), timeout = self.target.timeout)
				except Exception as e:
					pass
			
			logger.debug('Terminate 4!')
			#terminating TCP connection
			await asyncio.wait_for(self.disconnect(), timeout = self.target.timeout)
			logger.debug('Terminate finished!')	
		except:
			logger.exception('')
			
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
	connection = SMBConnection(spneg, [NegotiateDialects.SMB210])
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
	
async def test_high(target):
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
	connection = SMBConnection(spneg, [NegotiateDialects.SMB210])
	await connection.connect(target)
	await connection.negotiate()
	await connection.session_setup()
	
	end = SMBEndpoint()
	end.connection = connection
	
	await end.test()
	
async def test_kerberos(target):
	settings = {
		'mode' : 'CLIENT',
		'connection_string' : 'TEST/victim/pass:Passw0rd!1@10.10.10.2',
		'target_string': 'cifs/WIN2019AD@TEST.CORP',
		'dc_ip' : '10.10.10.2',
	}
	
	handler = SMBKerberos(settings)
	
	#setting up SPNEGO
	spneg = SPNEGO()
	spneg.add_auth_context('MS KRB5 - Microsoft Kerberos 5', handler)
	connection = SMBConnection(spneg, [NegotiateDialects.SMB210])
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

async def test_sspi_kerberos(target):
	settings = {
		'mode' : 'CLIENT',
		'username' : None,
		'password' : None,
		'target' : 'WIN2019AD',
	}
	handler = SMBKerberosSSPI(settings)
	#setting up SPNEGO
	spneg = SPNEGO()
	spneg.add_auth_context('MS KRB5 - Microsoft Kerberos 5', handler)
	connection = SMBConnection(spneg, [NegotiateDialects.SMB210])
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
	
async def test_sspi_ntlm(target):
	settings = {
		'mode' : 'CLIENT',
	}
	handler = SMBNTLMSSPI(settings)
	#setting up SPNEGO
	spneg = SPNEGO()
	spneg.add_auth_context('NTLMSSP - Microsoft NTLM Security Support Provider', handler)
	connection = SMBConnection(spneg, [NegotiateDialects.SMB210])
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
	
	await connection.terminate()
	
async def connection_test(target):
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
	connection = SMBConnection(spneg, [NegotiateDialects.SMB210])
	await connection.connect(target)
	await connection.negotiate()
	await connection.session_setup()
	#input(connection.get_extra_info())
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
	data, remaining = await connection.read(tree_id, file_id, offset = 100, length = 60000)
	
	print(data)
	print(remaining)
	
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
	await connection.terminate()
	print(str(info))
	
async def filereader_test(target):
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
	async with SMBConnection(spneg, target) as connection: 
		await connection.login()
		
		async with SMBFileReader(connection) as reader:
			await reader.open('\\\\10.10.10.2\\Users\\Administrator\\Desktop\\smb_test\\testfile1.txt')
			data = await reader.read()
			print(data)
			await reader.seek(0,0)
			data = await reader.read()
			print(data)
			await reader.seek(10,0)
			data = await reader.read()
			print(data)
			await reader.seek(10,0)
			data = await reader.read(5)
			print(data)
			await reader.seek(-10,2)
			data = await reader.read(5)
			print(data)
	
	
			
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
	
	