import enum
import asyncio
import hmac
import hashlib
import platform
import copy
import datetime
import traceback
from typing import cast
import pathlib

from aiosmb import logger
from aiosmb.commons.exceptions import *
from aiosmb.protocol.smb.command_codes import SMBCommand
from aiosmb.wintypes.ntstatus import NTStatus
from aiosmb.protocol.smb.header import SMBHeader, SMBHeaderFlags2Enum, SMBHeaderFlagsEnum
from aiosmb.protocol.smb.message import SMBMessage
from aiosmb.protocol.smb.commands import *
from aiosmb.protocol.smb2.message import SMB2Message, SMB2Transform, SMB2Compression
from aiosmb.protocol.smb2.commands import *
from aiosmb.protocol.smb2.headers import *
from aiosmb.protocol.smb2.command_codes import *
from aiosmb.protocol.smb.commons import SMBSecurityMode
from aiosmb.protocol.common import *
from aiosmb.wintypes.dtyp.constrcuted_security.guid import *
from aiosmb.wintypes.access_mask import *
from aiosmb.wintypes.fscc.structures.fileinfoclass import *
from aiosmb.wintypes.fscc.structures.FileFullDirectoryInformation import *
from aiosmb.wintypes.fscc.FileAttributes import FileAttributes
from aiosmb.protocol.smb2.commands.negotiate import SMB2ContextType, SMB2PreauthIntegrityCapabilities, SMB2HashAlgorithm, SMB2Cipher, SMB2CompressionType, SMB2CompressionFlags, SMB2EncryptionCapabilities, SMB2CompressionCapabilities
from aiosmb.protocol.smb2.commands.sessionsetup import SessionSetupCapabilities
from aiosmb.protocol.smb2.commands.tree_connect import ShareType
from aiosmb.protocol.smb2.commands.ioctl import VALIDATE_NEGOTIATE_INFO_REPLY, IOCTL_REPLY
from aiosmb.protocol.smb2.commands.create import CreateAction
from aiosmb.dcerpc.v5.servers.transport.smbtransport import DCERPCServerSMBTransport



from aiosmb.crypto.symmetric import aesCCMEncrypt, aesCCMDecrypt
from aiosmb.crypto.BASE import cipherMODE
from aiosmb.crypto.from_impacket import KDF_CounterMode, AES_CMAC
from aiosmb.crypto.compression.lznt1 import compress as lznt1_compress
from aiosmb.crypto.compression.lznt1 import decompress as lznt1_decompress

from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR
from winacl.functions.constants import SE_OBJECT_TYPE

#from aiosmb.commons.smbcontainer import *
#from aiosmb.commons.smbtarget import *



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

class SMBServerClientSession:
	def __init__(self):
		self.credential = None

class SMBServerSettings:
	def __init__(self,gssapi):
		self.gssapi = gssapi
		self.preferred_dialects = [NegotiateDialects.SMB202]
		self.MaxTransactSize = 0x100000
		self.MaxReadSize = 0x100000
		self.MaxWriteSize = 0x100000
		self.ServerGuid = GUID.random()
		self.RequireSigning = False

		self.shares = {} #share_name -> path on disk
	

class SMBServerConnection:
	def __init__(self, settings, transport, shutdown_evt = asyncio.Event()):
		self.settings = settings
		self.gssapi = self.settings.gssapi
		
		#######DONT CHANGE THIS
		#use this for smb2 > self.supported_dialects = [NegotiateDialects.WILDCARD, NegotiateDialects.SMB202, NegotiateDialects.SMB210]
		#self.supported_dialects = [NegotiateDialects.SMB202, NegotiateDialects.SMB210]
		self.supported_dialects = self.settings.preferred_dialects #[NegotiateDialects.WILDCARD, NegotiateDialects.SMB311]
		#######
		
		
		self.network_transport = None 
		self.transport = transport
		self.incoming_task = None
		# TODO: turn it back on 
		self.activity_at = None
		
		self.selected_dialect = None
		self.signing_required = self.settings.RequireSigning
		self.encryption_required = False
		self.last_treeid = 10
		
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
		self.MaxTransactSize = self.settings.MaxTransactSize
		self.MaxReadSize = self.settings.MaxReadSize
		self.MaxWriteSize = self.settings.MaxWriteSize
		self.ServerGuid = self.settings.ServerGuid
		#self.ServerName = None
		self.ClientGUID = None

		#self.Dialect = 0
		self.SupportsFileLeasing = False
		self.SupportsMultiCredit = False
		
		self.SupportsDirectoryLeasing = False
		self.SupportsMultiChannel = False
		self.SupportsPersistentHandles = False
		self.SupportsEncryption = False
		self.ClientCapabilities = 0
		self.ServerCapabilities = NegotiateCapabilities.DFS | NegotiateCapabilities.LARGE_MTU
		self.ClientSecurityMode = 0
		self.ServerSecurityMode = NegotiateSecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED
		if self.signing_required is True:
			self.ServerSecurityMode |= NegotiateSecurityMode.SMB2_NEGOTIATE_SIGNING_REQUIRED
		
		
		self.SessionId = 0
		self.SessionKey = None
		self.SigningKey      = None
		self.ApplicationKey  = None
		self.EncryptionKey   = None
		self.DecryptionKey   = None

		
		

		### SMB311 global
		self.CompressAllRequests = False

		### SMB311 transport
		self.PreauthIntegrityHashId = SMB2HashAlgorithm.SHA_512 #the type of the hash function was negotiated , now there is only one type
		self.PreauthIntegrityHashValue = b'\x00'*64 #The preauthentication integrity hash value that was computed for the exchange of SMB2 NEGOTIATE request and response messages on this connection.
		self.CompressionId = None #the selected compression
		self.CipherId = None #
		self.CompressionIds = [SMB2CompressionType.LZNT1]#[SMB2CompressionType.NONE] #list of supported compression
		self.SupportsChainedCompression = False
		self.smb2_supported_encryptions = [SMB2Cipher.AES_128_CCM, SMB2Cipher.AES_128_GCM]
		
		self.preauth_ctx = hashlib.sha512

		#ignore_close is there to skip the logoff/closing of the channel
		#this is useful because there could be certain errors after a scusessful logon
		#that invalidates the whole session (eg. STATUS_USER_SESSION_DELETED)
		#if this happens then logoff will fail as well!
		self.session_closed = False 

	def get_extra_info(self):
		try:
			ntlm_data = self.gssapi.get_extra_info()
			if ntlm_data is not None:
				ntlm_data = ntlm_data.to_dict()
		except:
			traceback.print_exc()
			ntlm_data = None
		if self.ServerSecurityMode is not None:
			return {
				'ntlm_data' : ntlm_data,
				'signing_enabled' : NegotiateSecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED in self.ServerSecurityMode,
				'signing_required' : NegotiateSecurityMode.SMB2_NEGOTIATE_SIGNING_REQUIRED in self.ServerSecurityMode,
			}
		return None

	async def run(self):
		self.incoming_task = self.__handle_smb_in()
		await self.incoming_task

	async def __handle_smb_in(self):
		"""
		Waits from SMB message bytes from the transport in_queue, and fills the connection table.
		This function started automatically when calling connect.
		Pls don't touch it.
		"""
		try:
			while True:
				print(1)
				msg_data, err = await self.transport.in_queue.get()
				print(msg_data)
				print(err)
				self.activity_at = datetime.datetime.utcnow()
				if err is not None:
					raise err
					#logger.debug('__handle_smb_in got error from transport layer %s' % err)
					#setting all outstanding events to finished
					for mid in self.OutstandingResponsesEvent:
						self.OutstandingResponses[mid] = (None, err)
						self.OutstandingResponsesEvent[mid].set()

					await self.terminate()
					return

				if msg_data[0] < 252:
					raise Exception('Unknown SMB packet type %s' % msg_data[0])

				if msg_data[0] == 0xFD:
					#encrypted transform
					msg = SMB2Transform.from_bytes(msg_data)
					
					if msg.header.EncryptionAlgorithm == SMB2Cipher.AES_128_CCM:
						dec_data = aesCCMDecrypt(msg.data, msg_data[20:], self.DecryptionKey, msg.header.Nonce[:11], msg.header.Signature)
						#print('dec_data %s' % dec_data)
						#cipher = AES(self.DecryptionKey, mode = cipherMODE.CCM, nonce = msg.header.Nonce[:11])
						#cipher.update(msg_data[20:])
						#dec_data = cipher.decrypt(msg.data)
						#calc_signature = cipher.verify()


						#cipher = AES.new(self.DecryptionKey, AES.MODE_CCM, msg.header.Nonce[:11])
						#cipher.update(msg_data[20:])
						#dec_data = cipher.decrypt(msg.data)
						##calc_signature = cipher.verify()

						# TODO: add signature checking!!!!!

						msg_data = dec_data
					
					else:
						raise Exception('Common encryption algo is %s but it is not implemented!' % msg.header.EncryptionAlgorithm)

				if msg_data[0] == 0xFC:
					#compressed transform
					msg = SMB2Compression.from_bytes(msg_data)
					if msg.header.Flags == SMB2CompressionFlags.NONE:
						if msg.header.CompressionAlgorithm != self.CompressionId:
							logger.debug('Server is using a different compression algo than whats agreed upon...')
						if msg.header.CompressionAlgorithm == SMB2CompressionType.LZNT1:
							uncompressed_data = msg.data[:msg.header.Offset]
							uncompressed_data += lznt1_decompress(msg.data[msg.header.Offset:])
							msg_data = uncompressed_data
						else:
							raise Exception('Server used %s compression, but it is not implemented' % msg.header.CompressionAlgorithm.name)
					else:
						raise Exception('Server sent chained compression, but its not implemented here')
					
				if msg_data[0] == 0xFE:
					#version2
					msg = SMB2Message.from_bytes(msg_data)
					if self.status == SMBConnectionStatus.NEGOTIATING:
						await self.negotiate(msg)
					elif self.status == SMBConnectionStatus.SESSIONSETUP:
						await self.session_setup(msg)
					
					elif self.status == SMBConnectionStatus.RUNNING:
						if msg.header.Command == SMB2Command.TREE_CONNECT:
							await self.tree_connect(msg)
						elif msg.header.Command == SMB2Command.CREATE:
							await self.create(msg)
						elif msg.header.Command == SMB2Command.IOCTL:
							await self.ioctl(msg)

							

				if msg_data[0] == 0xFF:
					#version1
					msg = SMBMessage.from_bytes(msg_data)
					if self.status == SMBConnectionStatus.NEGOTIATING:
						if msg.header.Command == SMBCommand.SMB_COM_NEGOTIATE:
							await self.negotiate(msg)
					else:
						print('SMBv1 message recieved! This is unexpected! %s' % msg.header.Command)
						continue

				logger.log(1, '__handle_smb_in got new message with Id %s' % msg.header.MessageId)
				
				
				
				#print(msg)
				
				#if msg.header.Status == NTStatus.PENDING:
				#	self.pending_table[msg.header.MessageId] = SMBPendingMsg(msg.header.MessageId, self.OutstandingResponses, self.OutstandingResponsesEvent, timeout = self.target.PendingTimeout, max_renewal=self.target.PendingMaxRenewal)
				#	await self.pending_table[msg.header.MessageId].run()
				#	continue

				if msg.header.MessageId in self.pending_table:
					await self.pending_table[msg.header.MessageId].stop()
					del self.pending_table[msg.header.MessageId]

				#self.OutstandingResponses[msg.header.MessageId] = (msg, msg_data)
				#if msg.header.MessageId in self.OutstandingResponsesEvent:
				#	self.OutstandingResponsesEvent[msg.header.MessageId].set()
				#else:
				#
				#	#here we are loosing messages, the functionality for "PENDING" and "SHARING_VIOLATION" should be implemented
				#	continue
		except asyncio.CancelledError:
			#the SMB connection is terminating
			return
		except:
			traceback.print_exc()

		
	async def disconnect(self):
		"""
		"""
		self.status = SMBConnectionStatus.CLOSED
		try:
			if self.transport is not None:
				await self.transport.stop()
		except:
			pass
		try:
			if self.network_transport is not None:
				await self.network_transport.disconnect()
		except:
			pass
		
		if self.incoming_task is not None:
			self.incoming_task.cancel()
	

	def update_integrity(self, msg_data):
		#if is_neg is True:
		#	self.PreauthIntegrityHashValue = b'\x00'*64
		#print('update_integrity with data : %s' % msg_data)
		ctx = hashlib.sha512()
		ctx.update(self.PreauthIntegrityHashValue + msg_data)
		self.PreauthIntegrityHashValue = ctx.digest()
		
	async def negotiate(self, req):
		try:
			print(req.command.Dialects)
			if (isinstance(req, SMBMessage) and 'SMB 2.???' in req.command.Dialects) or isinstance(req, SMB2Message):
					#if NegotiateDialects.WILDCARD in self.supported_dialects:
					reply = SMB2Message()
					reply.command = NEGOTIATE_REPLY()
					reply.command.SecurityMode = self.ServerSecurityMode
					reply.command.DialectRevision = NegotiateDialects.SMB202
					reply.command.NegotiateContextCount = 0
					reply.command.ServerGuid = self.ServerGuid
					reply.command.Capabilities = self.ServerCapabilities
					reply.command.MaxTransactSize = self.MaxTransactSize
					reply.command.MaxReadSize = self.MaxReadSize
					reply.command.MaxWriteSize = self.MaxWriteSize
					reply.command.SystemTime = datetime.datetime.utcnow()
					reply.command.ServerStartTime = datetime.datetime.utcnow()
					reply.command.SecurityBuffer = self.gssapi.get_mechtypes_list()
					reply.command.NegotiateContextOffset = 0
					reply.command.NegotiateContextList = []
					
					reply.header = SMB2Header_SYNC()
					reply.header.Command  = SMB2Command.NEGOTIATE
					reply.header.Flags = SMB2HeaderFlag.SMB2_FLAGS_SERVER_TO_REDIR
					reply.header.CreditCharge = 1
					await self.sendSMB(reply)

					self.selected_dialect = NegotiateDialects.SMB202

					
					self.SupportsMultiChannel = NegotiateCapabilities.MULTI_CHANNEL in self.ServerCapabilities
					self.SupportsFileLeasing = NegotiateCapabilities.LEASING in self.ServerCapabilities
					self.SupportsMultiCredit = NegotiateCapabilities.LARGE_MTU in self.ServerCapabilities
					
					self.status = SMBConnectionStatus.SESSIONSETUP
			return
		except Exception as e:
			traceback.print_exc()
		"""	
				###let's construct an SMBv1 SMB_COM_NEGOTIATE_REQ packet
				header = SMBHeader()
				header.Command  = SMBCommand.SMB_COM_NEGOTIATE
				header.Status   = NTStatus.SUCCESS
				header.Flags    = SMBHeaderFlagsEnum.SMB_FLAGS_REPLY
				header.Flags2   = SMBHeaderFlags2Enum.SMB_FLAGS2_UNICODE
					
				command = SMB_COM_NEGOTIATE_REQ()		
				command.Dialects = ['SMB 2.???','SMB 2.002']
				
				msg = SMBMessage(header, command)
				message_id = await self.sendSMB(msg)
				#recieveing reply, should be version2, because currently we dont support v1 :(
				rply, rply_data = await self.recvSMB(message_id, ret_data = True) #negotiate MessageId should be 1
				if isinstance(rply, SMBMessage):
					if protocol_test is True:
						if rply.command.DialectIndex == 65535:
							return False, rply, None
						return True, rply, None
					else:
						raise Exception('Server replied with SMBv1 message, doesnt support SMBv2')
				if rply.header.Status != NTStatus.SUCCESS:
					raise Exception('SMB2 negotiate error! Server replied with error status code!')
				
				del self.supported_dialects[NegotiateDialects.WILDCARD]

				#print(rply.command.Capabilities)

			command = NEGOTIATE_REQ()
			command.SecurityMode    = self.ClientSecurityMode
			command.Capabilities    = 0
			command.ClientGuid      = self.ClientGUID
			command.Dialects        = [dialect for dialect in self.supported_dialects]

			#if all(dialect in SMB2_NEGOTIATE_DIALTECTS_2 for dialect in self.supported_dialects):
			#	command.Capabilities    = NegotiateCapabilities.ENCRYPTION
			if all(dialect in SMB2_NEGOTIATE_DIALTECTS_3 for dialect in self.supported_dialects):
				command.Capabilities    = NegotiateCapabilities.ENCRYPTION


			if NegotiateDialects.SMB311 in self.supported_dialects:
				#SMB311 mandates the contextlist to be populated
							
				command.NegotiateContextList.append(
					SMB2PreauthIntegrityCapabilities.construct(
						[self.PreauthIntegrityHashId]
					)
				)
							
				if self.smb2_supported_encryptions is not None:
					command.Capabilities |= NegotiateCapabilities.ENCRYPTION
					command.NegotiateContextList.append(
						SMB2EncryptionCapabilities.from_enc_list(
							self.smb2_supported_encryptions
						)
					)

				if self.CompressionIds is not None:
					command.NegotiateContextList.append(
						SMB2CompressionCapabilities.from_comp_list(
							self.CompressionIds,
							self.SupportsChainedCompression
						)
					)
			
			header = SMB2Header_SYNC()
			header.Command  = SMB2Command.NEGOTIATE
			header.CreditReq = 0
						
			msg = SMB2Message(header, command)
			message_id = await self.sendSMB(msg)
			rply, rply_data = await self.recvSMB(message_id, ret_data=True) #negotiate MessageId should be 1
			if isinstance(rply, SMBMessage):
				raise Exception('Server replied with SMBv1 message, doesnt support SMBv2')
			self.update_integrity(rply_data)
			
			if rply.header.Status != NTStatus.SUCCESS:
				if rply.header.Status == NTStatus.NOT_SUPPORTED:
					raise Exception('negotiate_1 dialect probably not suppported by the server. reply: %s' % rply.header.Status)
				else:
					raise Exception('negotiate_1 reply: %s' % rply.header.Status)
						
			if rply.command.DialectRevision not in self.supported_dialects:
				raise SMBUnsupportedDialectSelected()
					
			self.selected_dialect = rply.command.DialectRevision
			self.ServerSecurityMode = rply.command.SecurityMode
			self.signing_required = NegotiateSecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED in rply.command.SecurityMode
			
					
			if NegotiateCapabilities.ENCRYPTION in rply.command.Capabilities:
				self.encryption_required = True
				self.CipherId = SMB2Cipher.AES_128_CCM

			for negctx in rply.command.NegotiateContextList:
				if negctx.ContextType == SMB2ContextType.ENCRYPTION_CAPABILITIES:
					self.encryption_required = True
					self.CipherId = negctx.Ciphers[0]
						
				if negctx.ContextType == SMB2ContextType.COMPRESSION_CAPABILITIES:
					self.CompressionId = negctx.CompressionAlgorithms[0]

			logger.log(1, 'Server selected dialect: %s' % self.selected_dialect)
					
			self.MaxTransactSize = min(self.MaxTransactSize, rply.command.MaxTransactSize)
			self.MaxReadSize = min(self.MaxReadSize, rply.command.MaxReadSize)
			self.MaxWriteSize = min(self.MaxWriteSize, rply.command.MaxWriteSize)
			self.ServerGuid = rply.command.ServerGuid
			self.SupportsMultiChannel = NegotiateCapabilities.MULTI_CHANNEL in rply.command.Capabilities
			self.SupportsFileLeasing = NegotiateCapabilities.LEASING in rply.command.Capabilities
			self.SupportsMultiCredit = NegotiateCapabilities.LARGE_MTU in rply.command.Capabilities
					
			self.ClientCapabilities = rply.command.Capabilities
			self.ServerCapabilities = rply.command.Capabilities
			#self.ClientSecurityMode = 0			
			self.status = SMBConnectionStatus.SESSIONSETUP
			
			if protocol_test is True:
				return True, rply, None
			return True, None
		
		"""

	async def session_setup(self, msg):
		try:
			maxiter = 5
			if self.SessionId == 0:
				self.SessionId += 1
			while maxiter > 0:
				reply = SMB2Message()
				reply.command = SESSION_SETUP_REPLY()
				reply.command.SessionFlags = 0
				try:
					reply.command.Buffer, to_continue, err  = await self.gssapi.authenticate(msg.command.Buffer)
					print(reply.command.Buffer)
					print(to_continue)
					if err is not None:
						raise err
					
				except Exception as e:
					logger.exception('GSSAPI auth failed!')
					#TODO: Clear this up, kerberos lib needs it's own exceptions!
					if str(e).find('Preauth') != -1:
						raise SMBKerberosPreauthFailed()
					else:
						raise e
						#raise SMBKerberosPreauthFailed()
				
				reply.header = SMB2Header_SYNC()
				reply.header.Command  = SMB2Command.SESSION_SETUP
				reply.header.Flags = SMB2HeaderFlag.SMB2_FLAGS_SERVER_TO_REDIR
				reply.header.SessionId = self.SessionId
				
				reply.header.CreditCharge = 1
				reply.header.CreditReq = 1
				reply.header.Status = NTStatus.SUCCESS if to_continue is False else NTStatus.MORE_PROCESSING_REQUIRED
				print(reply.header.Status)
				
				if to_continue is False:
					self.SessionKey = self.gssapi.get_session_key()[:16]
					reply.header.Flags |= SMB2HeaderFlag.SMB2_FLAGS_SIGNED
					reply.header.CreditReq = 127
					self.status = SMBConnectionStatus.RUNNING
				
				await self.sendSMB(reply)
				return
			"""
				message_id = await self.sendSMB(msg)
				#self.update_integrity(sent_msg.to_bytes())
				rply, rply_data = await self.recvSMB(message_id, ret_data=True)
				
				if self.SessionId == 0:
					self.SessionId = rply.header.SessionId
				
				if rply.header.Status not in [NTStatus.SUCCESS, NTStatus.MORE_PROCESSING_REQUIRED]:
					break

				if rply.header.Status != NTStatus.SUCCESS:
					self.update_integrity(rply_data)
				
				authdata = rply.command.Buffer
				status = rply.header.Status
				maxiter -= 1
			
			if rply.header.Status == NTStatus.SUCCESS:
				command.Buffer, res, err  = await self.gssapi.authenticate(authdata)
				if err is not None:
					raise err


				if self.gssapi.is_guest() is True:
					self.signing_required = False

				self.SessionKey = self.gssapi.get_session_key()[:16]
				
				# TODO: key calc
				if self.signing_required and self.selected_dialect in [NegotiateDialects.SMB300 , NegotiateDialects.SMB302 , NegotiateDialects.SMB311]:
					if  self.selected_dialect == NegotiateDialects.SMB311:
						#SMB311 is a special snowflake
						self.SigningKey      = KDF_CounterMode(self.SessionKey, b"SMBSigningKey\x00", self.PreauthIntegrityHashValue, 128)
						self.ApplicationKey  = KDF_CounterMode(self.SessionKey, b"SMBAppKey\x00", self.PreauthIntegrityHashValue, 128)
						self.EncryptionKey   = KDF_CounterMode(self.SessionKey, b"SMBC2SCipherKey\x00", self.PreauthIntegrityHashValue, 128)
						self.DecryptionKey   = KDF_CounterMode(self.SessionKey, b"SMBS2CCipherKey\x00", self.PreauthIntegrityHashValue, 128)
					else:
						self.SigningKey      = KDF_CounterMode(self.SessionKey, b"SMB2AESCMAC\x00", b"SmbSign\x00", 128)
						self.ApplicationKey  = KDF_CounterMode(self.SessionKey, b"SMB2APP\x00", b"SmbRpc\x00", 128)
						self.EncryptionKey   = KDF_CounterMode(self.SessionKey, b"SMB2AESCCM\x00", b"ServerIn \x00", 128)
						self.DecryptionKey   = KDF_CounterMode(self.SessionKey, b"SMB2AESCCM\x00", b"ServerOut\x00", 128)
				
				self.status = SMBConnectionStatus.RUNNING
			
			elif rply.header.Status == NTStatus.LOGON_FAILURE:
				raise SMBAuthenticationFailed()
			
			else:
				raise SMBException('session_setup (authentication probably failed)', rply.header.Status)
		
			return True, None
			"""
		except Exception as e:
			traceback.print_exc()
			reply = SMB2Message()
			reply.command = SESSION_SETUP_REPLY()
			reply.command.SessionFlags = 0
			reply.command.Buffer = b''				
			reply.header = SMB2Header_SYNC()
			reply.header.Command  = SMB2Command.SESSION_SETUP
			reply.header.Flags = SMB2HeaderFlag.SMB2_FLAGS_SERVER_TO_REDIR
			reply.header.CreditReq = 0
			reply.header.Status = NTStatus.ACCESS_DENIED
			print(reply.header.Status)
			await self.sendSMB(reply)

			
		
		
	async def recvSMB(self, message_id, ret_data = False):
		"""
		Returns an SMB message from the outstandingresponse dict, OR waits until the expected message_id appears.
		"""
		if message_id not in self.OutstandingResponses:
			logger.log(1, 'Waiting on messageID : %s' % message_id)
			await self.OutstandingResponsesEvent[message_id].wait() #TODO: add timeout here?
			
		msg, msg_data = self.OutstandingResponses.pop(message_id)
		if msg is None:
			# this indicates and exception, so the msg_data is the exception
			raise msg_data
		
		if self.status != SMBConnectionStatus.NEGOTIATING:
			if self.selected_dialect != NegotiateDialects.SMB202:
				self.SequenceWindow += (msg.header.CreditCharge - 1)

		if msg.header.Status != NTStatus.PENDING:
			if message_id in self.OutstandingResponsesEvent:
				del self.OutstandingResponsesEvent[message_id]
		else:
			self.OutstandingResponsesEvent[message_id].clear()
		
		if ret_data is False:
			return msg
		return msg, msg_data
		
	def sign_message(self, msg):
		if self.selected_dialect in [NegotiateDialects.SMB202, NegotiateDialects.SMB210]:
			print(self.SessionKey)

			if self.SessionKey:
				msg.header.Flags = msg.header.Flags ^ SMB2HeaderFlag.SMB2_FLAGS_SIGNED ##maybe move this flag settings to sendsmb since singing is determined there?
				digest = hmac.new(self.SessionKey, msg.to_bytes(), hashlib.sha256).digest()
				msg.header.Signature = digest[:16]
		else:
			if self.SigningKey:
				msg_data = msg.to_bytes()	
				signature = AES_CMAC(self.SigningKey, msg_data, len(msg_data))
				msg.header.Signature = signature

	
	def encrypt_message(self, msg_data):
		nonce = os.urandom(11)

		hdr = SMB2Header_TRANSFORM()
		#hdr.Signature = None
		hdr.Nonce = nonce + (b'\x00' * 5) 
		hdr.OriginalMessageSize = len(msg_data)
		hdr.EncryptionAlgorithm = SMB2Cipher.AES_128_CCM
		hdr.SessionId = self.SessionId

		enc_data, hdr.Signature = aesCCMEncrypt(msg_data, hdr.to_bytes()[20:], self.EncryptionKey, nonce)

		#cipher = AES.new(self.EncryptionKey, AES.MODE_CCM, nonce)
		#cipher.update(hdr.to_bytes()[20:])
		#enc_data = cipher.encrypt(msg_data)
		#hdr.Signature = cipher.digest()
		return SMB2Transform(hdr, enc_data)


	def compress_message(self, msg):
		msg_data = msg.to_bytes()
		
		if self.SupportsChainedCompression is False:
			if self.CompressionId == SMB2CompressionType.NONE:
				compressed_data = msg_data
			elif self.CompressionId == SMB2CompressionType.LZNT1:
				compressed_data = lznt1_compress(msg_data)
			else:
				raise Exception('Common compression type is %s but its not implemented!' % self.CompressionId)
			
			comp_hdr = SMB2Header_COMPRESSION_TRANSFORM()
			comp_hdr.OriginalCompressedSegmentSize = len(msg_data)
			comp_hdr.CompressionAlgorithm = self.CompressionId
			comp_hdr.Flags = SMB2CompressionFlags.NONE
			comp_hdr.Offset = 0 #it'z zero because we compress the full message

			return SMB2Compression(comp_hdr, compressed_data)
		else:
			raise Exception('Chained compression not implemented!')
		
	async def sendSMB(self, msg, ret_message = False, compression_cb = None):
		"""
		Sends an SMB message to teh remote endpoint.
		msg: SMB2Message or SMBMessage
		Returns: MessageId integer
		"""
		self.activity_at = datetime.datetime.utcnow()
		if self.status == SMBConnectionStatus.NEGOTIATING:
			if isinstance(msg, SMBMessage):
				#creating an event for outstanding response
				#self.OutstandingResponsesEvent[0] = asyncio.Event()
				#await self.transport.out_queue.put(msg.to_bytes())
				#self.SequenceWindow += 1
				#return 0
				message_id = 0
				self.SequenceWindow += 1
			else:
				msg.header.CreditCharge = 1
				if msg.header.CreditReq is None:
					msg.header.CreditReq = 1
				msg.header.MessageId = self.SequenceWindow
				message_id = self.SequenceWindow
				self.SequenceWindow += 1
				self.update_integrity(msg.to_bytes())

			self.OutstandingResponsesEvent[message_id] = asyncio.Event()
			await self.transport.out_queue.put(msg.to_bytes())
			if ret_message is True:
				return message_id, msg
			return message_id
				
		print('RUNNING')
		print(self.signing_required)
		if msg.header.Command is not SMB2Command.CANCEL:
			msg.header.MessageId = self.SequenceWindow
			self.SequenceWindow += 1
		
		msg.header.SessionId = self.SessionId
		
		if not msg.header.CreditCharge:
			msg.header.CreditCharge = 0

		
		
		if self.status != SMBConnectionStatus.SESSIONSETUP:
			msg.header.CreditReq = 127
		
		message_id = msg.header.MessageId
		#print(msg)

		if self.CompressionId is not None and self.EncryptionKey is not None:
			if compression_cb is None:
				msg = self.compress_message(msg)
			else:
				msg = compression_cb(msg)
		if self.signing_required == True:
			self.sign_message(msg)
		
		if self.encryption_required == True and self.EncryptionKey is not None:
			msg = self.encrypt_message(msg.to_bytes())

		else:
			self.update_integrity(msg.to_bytes())

		#creating an event for outstanding response
		self.OutstandingResponsesEvent[message_id] = asyncio.Event()
		await self.transport.out_queue.put(msg.to_bytes())
		
		if ret_message is True:
				return message_id, msg
		return message_id
		
	async def tree_connect(self, msg):
		try:
			print('path %s' % msg.command.Path)
			path = msg.command.Path.split('\\')[-1]
			if path.upper() == 'IPC$':
				print(path)
				reply = SMB2Message()
				reply.command = TREE_CONNECT_REPLY()
				reply.command.ShareType = ShareType.PIPE
				reply.command.ShareFlags = ShareFlags.SMB2_SHAREFLAG_NO_CACHING
				reply.command.Capabilities = TreeCapabilities.SMB2_SHARE_CAP_NONE
				reply.command.MaximalAccess = FileAccessMask.GENERIC_ALL
					
				reply.header = SMB2Header_SYNC()
				reply.header.Command  = SMB2Command.TREE_CONNECT
				reply.header.Flags = SMB2HeaderFlag.SMB2_FLAGS_SERVER_TO_REDIR
				reply.header.TreeId = self.last_treeid
				self.last_treeid += 1
				
				te = TreeEntry.from_tree_reply(reply, path.upper())
				self.TreeConnectTable_id[reply.header.TreeId] = te
				self.TreeConnectTable_share[path.upper()] = te
				
				await self.sendSMB(reply)

			return
			
			if rply.header.Status == NTStatus.SUCCESS:
				te = TreeEntry.from_tree_reply(rply, share_name)
				self.TreeConnectTable_id[rply.header.TreeId] = te
				self.TreeConnectTable_share[share_name] = te
				return te, None
			
			elif rply.header.Status == NTStatus.BAD_NETWORK_NAME:
				raise SMBIncorrectShareName()
				
			elif rply.header.Status == NTStatus.USER_SESSION_DELETED:
				self.session_closed = True
				raise SMBException('session delted', NTStatus.USER_SESSION_DELETED)
			
			
			else:
				raise SMBException('', rply.header.Status)
		
		except Exception as e:
			traceback.print_exc()
		
	async def create(self, msg):
		try:
			print(msg)
			print(msg.header)
			print(msg.command)
			print(self.TreeConnectTable_id)
			if msg.header.TreeId not in self.TreeConnectTable_id:
				raise Exception('Unknown Tree ID!')
			
			tree_entry = self.TreeConnectTable_id[msg.header.TreeId]
			print(tree_entry)
			if tree_entry.share_name == 'IPC$':

				if msg.command.Name.lower() == 'srvsvc':
					
					from aiosmb.dcerpc.v5.servers.srvsvc import SRVSVCServer
					in_q = asyncio.Queue()
					out_q = asyncio.Queue()
					transport = DCERPCServerSMBTransport(in_q, out_q)
					server = SRVSVCServer(transport, self.settings.shares)
					await server.run()


				else:
					raise NotImplementedError()

				#self.FileHandleTable
					
				reply = SMB2Message()
				reply.command = CREATE_REPLY()
				reply.command.OplockLevel = OplockLevel.SMB2_OPLOCK_LEVEL_NONE
				reply.command.Flags = CreateOptions.FILE_DIRECTORY_FILE
				reply.command.CreateAction = CreateAction.FILE_OPENED
				reply.command.CreationTime = 0
				reply.command.LastAccessTime = 0
				reply.command.LastWriteTime = 0
				reply.command.ChangeTime = 0
				reply.command.AllocationSize = 4096
				reply.command.EndofFile = 0
				reply.command.FileAttributes = FileAttributes.FILE_ATTRIBUTE_NORMAL
				reply.command.Reserved2 = 0
				reply.command.FileId = None
				reply.command.CreateContextsOffset = 0
				reply.command.CreateContextsLength = 0
						
				reply.header = SMB2Header_SYNC()
				reply.header.Command  = SMB2Command.CREATE
				reply.header.Flags = SMB2HeaderFlag.SMB2_FLAGS_SERVER_TO_REDIR
				reply.header.TreeId = msg.header.TreeId
					
				await self.sendSMB(reply)
			
			
			else:
				share_path = self.settings.shares[tree_entry.share_name]
				print(share_path)

			
		
		except Exception as e:
			traceback.print_exc()
	
	async def read(self, tree_id, file_id, offset = 0, length = 0):
		"""
		Will issue one read command only then waits for reply. To read a whole file you must use a filereader logic! 
		returns the data bytes and the remaining data length
		
		IMPORTANT: remaning data length is dependent on the length of the requested chunk (length param) not on the actual file length.
		to get the remaining length for the actual file you must set the length parameter to the correct file size!
		
		If and EOF happens the function returns an empty byte array and the remaining data is set to 0
		"""
		try:
			if self.session_closed == True:
				return None, None, None
				
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
				return rply.command.Buffer, rply.command.DataRemaining, None
			
			elif rply.header.Status == NTStatus.END_OF_FILE:
				return b'', 0, None
				
			else:
				raise SMBException('', rply.header.Status)

		except Exception as e:
			return None, None, e
			
			
	async def write(self, tree_id, file_id, data, offset = 0):
		"""
		This function will send one packet only! The data size can be larger than what one packet allows, but it will be truncated
		to the maximum. 
		Also, there is no guarantee that the actual sent data will be fully written to the remote file! This will be indicated in the returned value.
		Use a high-level function to get a full write.
		
		"""
		try:
			if self.session_closed == True:
				return None, None
				
			if tree_id not in self.TreeConnectTable_id:
				raise Exception('Unknown Tree ID! %s' % tree_id)
			if file_id not in self.FileHandleTable:
				raise Exception('Unknown File ID! %s' % file_id)
				
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
				return rply.command.Count, None
			
			else:
				raise SMBException('', rply.header.Status)
		except Exception as e:
			return None, e
		
	async def query_info(self, tree_id, file_id, info_type = QueryInfoType.FILE, information_class = FileInfoClass.FileStandardInformation, additional_information = 0, flags = 0, data_in = ''):
		"""
		Queires the file or directory for specific information. The information returned is depending on the input parameters, check the documentation on msdn for a better understanding.
		The resturned data can by raw bytes or an actual object, depending on wther your info is implemented in the library.
		Sorry there are a TON of classes to deal with :(
		
		IMPORTANT: in case you are requesting big amounts of data, the result will arrive in chunks. You will need to invoke this function until None is returned to get the full data!!!
		"""
		try:
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
					return SECURITY_DESCRIPTOR.from_bytes(rply.command.Data, object_type=SE_OBJECT_TYPE.SE_FILE_OBJECT), None
					
				elif info_type == QueryInfoType.FILE:
					if information_class == FileInfoClass.FileFullDirectoryInformation:
						return FileFullDirectoryInformationList.from_bytes(rply.command.Data), None
						
					else:
						return rply.command.Data, None
						
				elif info_type == QueryInfoType.FILESYSTEM:
					#TODO: implement this
					return rply.command.Data, None
					
				elif info_type == QueryInfoType.QUOTA:
					#TODO: implement this
					return rply.command.Data, None
				
				else:
					#this should never happen
					return rply.command.Data, None
				
			else:
				raise SMBException('', rply.header.Status)
		
		except Exception as e:
			return None, e
		
	async def query_directory(self, tree_id, file_id, search_pattern = '*', resume_index = 0, information_class = FileInfoClass.FileFullDirectoryInformation, maxBufferSize = None, flags = 0):
		"""
		
		IMPORTANT: in case you are requesting big amounts of data, the result will arrive in chunks. You will need to invoke this function until None is returned to get the full data!!!
		"""
		try:
			if self.session_closed == True:
				return None, None
				
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
					return FileFullDirectoryInformationList.from_bytes(rply.command.Data), None
					
				else:
					return rply.command.Data, None
					
			elif rply.header.Status == NTStatus.NO_MORE_FILES:
				return None, None
			else:
				raise Exception('query_directory reply: %s' % rply.header.Status)
		
		except Exception as e:
			return None, e

	async def ioctl(self, message:SMB2Message):
		try:
			## IOCTL commands not implemented!!!!
			reply = SMB2Message()
			reply.header = SMB2Header_SYNC()
			reply.header.Command  = SMB2Command.IOCTL
			reply.header.Flags = SMB2HeaderFlag.SMB2_FLAGS_SERVER_TO_REDIR
			reply.header.CreditReq = 64
			reply.header.Status = NTStatus.NOT_SUPPORTED
			reply.command = ERROR_REPLY()
			await self.sendSMB(reply)
			return

			if message.command.CtlCode == CtlCode.FSCTL_VALIDATE_NEGOTIATE_INFO:
				print(message.command.Buffer)

				

				data = VALIDATE_NEGOTIATE_INFO_REPLY()
				data.Guid = self.ServerGuid
				data.SecurityMode = self.ServerSecurityMode #NegotiateSecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED #NegotiateSecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED | NegotiateSecurityMode.SMB2_NEGOTIATE_SIGNING_REQUIRED # self.ServerSecurityMode
				data.Capabilities = self.ServerCapabilities
				data.Dialect = self.selected_dialect

				reply = SMB2Message()
				reply.command = IOCTL_REPLY()
				reply.command.Buffer = data.to_bytes()
				reply.command.CtlCode  = CtlCode.FSCTL_VALIDATE_NEGOTIATE_INFO #CtlCode MUST be set to FSCTL_VALIDATE_NEGOTIATE_INFO.
				reply.command.FileId  = b'\xFF'*16 #FileId MUST be set to { 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF }.
				reply.command.Flags = 0 #Flags MUST be set to zero.
				reply.command.InputOffset =  64+48# InputOffset SHOULD be set to the offset, in bytes, from the beginning of the SMB2 header to the Buffer[] field of the response.
				reply.command.InputCount = 0 #InputCount SHOULD be set to zero.
				reply.command.OutputOffset = reply.command.InputOffset + reply.command.InputCount #OutputOffset MUST be set to InputOffset + InputCount, rounded up to a multiple of 8.
				reply.command.OutputCount =  len(reply.command.Buffer) # OutputCount MUST be set to the size of the VALIDATE_NEGOTIATE_INFO response that is constructed as above.
				
				reply.header = SMB2Header_SYNC()
				reply.header.Command  = SMB2Command.IOCTL
				reply.header.Flags = SMB2HeaderFlag.SMB2_FLAGS_SERVER_TO_REDIR
				reply.header.CreditReq = 64
				await self.sendSMB(reply)
			else:
				raise NotImplementedError()
		except Exception as e:
			traceback.print_exc()
			return None, e
			
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
		"""
		try:					
			await self.disconnect()
		except asyncio.CancelledError:
			return
		except Exception as e:
			logger.debug('terminate error %s' % str(e))
	
	
	
			
if __name__ == '__main__':
	from aiosmb.network.servers.tcp import TCPServerSocket
	from aiosmb.authentication.spnego.native import SPNEGO
	from aiosmb.authentication.ntlm.native import NTLMAUTHHandler, NTLMHandlerSettings
	from aiosmb.commons.connection.credential import SMBNTLMCredential

	ip = '0.0.0.0'
	port = 445
	credential = SMBNTLMCredential()
	credential.username = 'WIN2019AD$'
	credential.domain = 'TEST'
	credential.workstation = None
	credential.is_guest = False
	credential.nt_hash = '933ad76b9665fb9d9cac27e2197c62c9'			
	authsettings = NTLMHandlerSettings(credential, mode = 'SERVER', template_name = 'Windows2003', custom_template = None)
	ctx = NTLMAUTHHandler(authsettings)
	gssapi = SPNEGO('SERVER')
	gssapi.add_auth_context('NTLMSSP - Microsoft NTLM Security Support Provider', ctx)
	server_settings = SMBServerSettings(gssapi)
	server_settings.RequireSigning = False
	server_settings.shares = {
		'shared' : '/home/devel/Desktop'
	}

	server = TCPServerSocket(ip, server_settings, port)
	asyncio.run(server.run())
	