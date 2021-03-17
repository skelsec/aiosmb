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
from aiosmb.protocol.smb.commons import SMBSecurityMode
from aiosmb.protocol.smb.commands import *
from aiosmb.protocol.smb2.message import SMB2Message, SMB2Transform, SMB2Compression
from aiosmb.protocol.smb2.commands.negotiate import SMB2ContextType, SMB2PreauthIntegrityCapabilities, SMB2HashAlgorithm, SMB2Cipher, SMB2CompressionType, SMB2CompressionFlags, SMB2EncryptionCapabilities, SMB2CompressionCapabilities
from aiosmb.protocol.smb2.commands import *
from aiosmb.protocol.smb2.headers import *
from aiosmb.protocol.smb2.command_codes import *
from aiosmb.protocol.common import *
from aiosmb.wintypes.dtyp.constrcuted_security.guid import *
from aiosmb.wintypes.access_mask import *
from aiosmb.wintypes.fscc.structures.fileinfoclass import *
from aiosmb.wintypes.fscc.structures.FileFullDirectoryInformation import *
from aiosmb.wintypes.fscc.FileAttributes import FileAttributes

from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR
from winacl.functions.constants import SE_OBJECT_TYPE

from aiosmb.commons.smbcontainer import *
from aiosmb.commons.connection.target import *

from aiosmb.crypto.symmetric import aesCCMEncrypt, aesCCMDecrypt
from aiosmb.crypto.BASE import cipherMODE
from aiosmb.crypto.from_impacket import KDF_CounterMode, AES_CMAC
from aiosmb.crypto.compression.lznt1 import compress as lznt1_compress
from aiosmb.crypto.compression.lznt1 import decompress as lznt1_decompress

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
		self.OutstandingResponses[self.message_id] = (None, problem)
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
	#def __init__(self, gssapi, target, dialects = [NegotiateDialects.SMB202]):
	def __init__(self, gssapi, target):
		self.gssapi = gssapi
		self.original_gssapi = copy.deepcopy(gssapi) #preserving a copy of the original
		
		self.target = target
		
		#######DONT CHANGE THIS
		#use this for smb2 > self.supported_dialects = [NegotiateDialects.WILDCARD, NegotiateDialects.SMB202, NegotiateDialects.SMB210]
		#self.supported_dialects = [NegotiateDialects.SMB202, NegotiateDialects.SMB210]
		self.supported_dialects = self.target.preferred_dialects #[NegotiateDialects.WILDCARD, NegotiateDialects.SMB311]
		#######
		
		self.settings = None
		self.network_transport = None 
		self.netbios_transport = None #this class is used by the netbios transport class, keeping it here also maybe you like to go in raw
		self.incoming_task = None
		self.keepalive_task = None
		# TODO: turn it back on 
		self.supress_keepalive = False
		self.activity_at = None
		
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
		self.MaxTransactSize = self.target.MaxTransactSize if self.target.MaxTransactSize is not None else 0x100000
		self.MaxReadSize = self.target.MaxReadSize if self.target.MaxReadSize is not None else 0x100000
		self.MaxWriteSize = self.target.MaxWriteSize if self.target.MaxWriteSize is not None else 0x100000
		self.ServerGuid = None
		self.RequireSigning = False
		self.ServerName = None
		self.ClientGUID = GUID.random()

		#self.Dialect = 0
		self.SupportsFileLeasing = False
		self.SupportsMultiCredit = False
		
		self.SupportsDirectoryLeasing = False
		self.SupportsMultiChannel = False
		self.SupportsPersistentHandles = False
		self.SupportsEncryption = False
		self.ClientCapabilities = 0
		self.ServerCapabilities = 0
		self.ClientSecurityMode = NegotiateSecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED | NegotiateSecurityMode.SMB2_NEGOTIATE_SIGNING_REQUIRED
		self.ServerSecurityMode = 0
		
		
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
		
	async def __aenter__(self):
		return self
		
	async def __aexit__(self, exc_type, exc, traceback):
		await asyncio.wait_for(self.terminate(), timeout = 1)

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

	async def __pending_task(self, message_id, timeout = 5):
		await asyncio.sleep(timeout)
		

	async def __handle_smb_in(self):
		"""
		Waits from SMB message bytes from the transport in_queue, and fills the connection table.
		This function started automatically when calling connect.
		Pls don't touch it.
		"""
		try:
			while True:
				msg_data, err = await self.netbios_transport.in_queue.get()
				self.activity_at = datetime.datetime.utcnow()
				if err is not None:
					logger.debug('__handle_smb_in got error from transport layer %s' % err)
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

				if msg_data[0] == 0xFF:
					#version1
					msg = SMBMessage.from_bytes(msg_data)
					

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

				self.OutstandingResponses[msg.header.MessageId] = (msg, msg_data)
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
		try:
			_, err = await self.connect()
			if err is not None:
				raise err

			_, err = await self.negotiate()
			if err is not None:
				raise err

			_, err = await self.session_setup()
			if err is not None:
				raise err
			
			self.keepalive_task = asyncio.create_task(self.keepalive())
			
			return True, None
		except Exception as e:
			await self.disconnect()
			return False, e
		
	async def fake_login(self):
		try:
			if 'NTLMSSP - Microsoft NTLM Security Support Provider' not in self.gssapi.authentication_contexts:
				raise Exception('Fake authentication is only supported via NTLM package')
			_, err = await self.connect()
			if err is not None:
				raise err
			_, err = await self.negotiate()
			if err is not None:
				raise err
			_, err = await self.session_setup(fake_auth = True)
			if err is not None:
				raise err
			
			return self.gssapi.get_extra_info(), None
		except Exception as e:
			return None, e
		finally:
			await self.disconnect()

	async def protocol_test(self, protocol):
		"""
		Checks if the remote end supports a given protocol.
		On success it returns True and the reply from the server (for checking SMB3 capabilities)
		"""
		try:
			self.supported_dialects = protocol
			_, err = await self.connect()
			if err is not None:
				raise err
			sign_en = None
			sign_req = None
			res, rply, err = await self.negotiate(protocol_test = True)
			if isinstance(rply, SMB2Message):
				sign_en = NegotiateSecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED in rply.command.SecurityMode   
				sign_req = NegotiateSecurityMode.SMB2_NEGOTIATE_SIGNING_REQUIRED in rply.command.SecurityMode   
			elif isinstance(rply, SMBMessage):
				sign_en = SMBSecurityMode.NEGOTIATE_SECURITY_SIGNATURES_ENABLED in rply.command.SecurityMode   
				sign_req = SMBSecurityMode.NEGOTIATE_SECURITY_SIGNATURES_REQUIRED in rply.command.SecurityMode   

			if err is not None:
				raise err

			return res, sign_en, sign_req, rply, None
		except Exception as e:
			return False, None, None, None, e
		finally:
			await self.disconnect()
	
	async def connect(self):
		"""
		Establishes socket connection to the remote endpoint. Also starts the internal reading procedures.
		"""
		try:
			self.network_transport, err = await NetworkSelector.select(self.target)
			if err is not None:
				raise err
			
			_, err = await self.network_transport.connect()
			if err is not None:
				raise err
			
			
			self.netbios_transport = NetBIOSTransport(self.network_transport)
			_, err = await self.netbios_transport.run()
			if err is not None:
				raise err

			self.incoming_task = asyncio.create_task(self.__handle_smb_in())
			return True, None
		except Exception as e:
			await self.disconnect()
			return False, e
		
	async def disconnect(self):
		"""
		Tears down the socket connecting as well as the reading cycle.
		Doesn't do any cleanup! 
		For proper cleanup call the terminate function.
		"""
		if self.status == SMBConnectionStatus.CLOSED:
			return
		
		self.status = SMBConnectionStatus.CLOSED
		try:
			if self.netbios_transport is not None:
				await self.netbios_transport.stop()
		except:
			pass
		try:
			if self.network_transport is not None:
				await self.network_transport.disconnect()
		except:
			pass
		
		if self.incoming_task is not None:
			self.incoming_task.cancel()
		
		if self.keepalive_task is not None:
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
				if (datetime.datetime.utcnow() - self.activity_at).seconds > sleep_time and self.supress_keepalive is False: 
					await self.echo()
				
		except asyncio.CancelledError:
			return
		except Exception as e:
			logger.debug('Keepalive failed! Server probably disconnected!')
			await self.disconnect()

	def update_integrity(self, msg_data):
		#if is_neg is True:
		#	self.PreauthIntegrityHashValue = b'\x00'*64
		#print('update_integrity with data : %s' % msg_data)
		ctx = hashlib.sha512()
		ctx.update(self.PreauthIntegrityHashValue + msg_data)
		self.PreauthIntegrityHashValue = ctx.digest()
		
	async def negotiate(self, protocol_test = False):
		"""
		Initiates protocol negotiation.
		First we send an SMB_COM_NEGOTIATE_REQ with our supported dialects
		"""
		try:
			rply = None
			if NegotiateDialects.WILDCARD in self.supported_dialects:
				###let's construct an SMBv1 SMB_COM_NEGOTIATE_REQ packet
				header = SMBHeader()
				header.Command  = SMBCommand.SMB_COM_NEGOTIATE
				header.Status   = NTStatus.SUCCESS
				header.Flags    = 0
				header.Flags2   = SMBHeaderFlags2Enum.SMB_FLAGS2_UNICODE
					
				command = SMB_COM_NEGOTIATE_REQ()
				if protocol_test is True:
					command.Dialects = ['NT LM 0.12']
				else:			
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
		
		except Exception as e:
			if protocol_test is True:
				return False, None, None
			return False, e

	async def session_setup(self, fake_auth = False):
		try:
			authdata = None
			status = NTStatus.MORE_PROCESSING_REQUIRED
			maxiter = 5
			while status == NTStatus.MORE_PROCESSING_REQUIRED and maxiter > 0:
				command = SESSION_SETUP_REQ()
				try:
					command.Buffer, res, err  = await self.gssapi.authenticate(authdata)
					if err is not None:
						raise err
					if fake_auth == True:
						if self.gssapi.selected_authentication_context is not None and self.gssapi.selected_authentication_context.ntlmChallenge is not None:
							return True, None
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
				command.Capabilities = 0 #self.ClientCapabilities
				command.Channel      = 0
				command.PreviousSessionId    = 0
				
				header = SMB2Header_SYNC()
				header.Command  = SMB2Command.SESSION_SETUP
				header.CreditReq = 0
				
				msg = SMBMessage(header, command)
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
		except Exception as e:
			return False, e
		
		
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
				#await self.netbios_transport.out_queue.put(msg.to_bytes())
				#self.SequenceWindow += 1
				#return 0
				message_id = 0
				self.SequenceWindow += 1
			else:
				msg.header.CreditCharge = 1
				msg.header.CreditReq = 0
				msg.header.MessageId = self.SequenceWindow
				message_id = self.SequenceWindow
				self.SequenceWindow += 1
				self.update_integrity(msg.to_bytes())

			self.OutstandingResponsesEvent[message_id] = asyncio.Event()
			await self.netbios_transport.out_queue.put(msg.to_bytes())
			if ret_message is True:
				return message_id, msg
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
		await self.netbios_transport.out_queue.put(msg.to_bytes())
		
		if ret_message is True:
				return message_id, msg
		return message_id
		
	async def tree_connect(self, share_name):
		"""
		share_name MUST be in "\\\\server\\share" format! Server can be NetBIOS name OR IP4 OR IP6 OR FQDN
		"""
		try:
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
				return te, None
			
			elif rply.header.Status == NTStatus.BAD_NETWORK_NAME:
				raise SMBIncorrectShareName()
				
			elif rply.header.Status == NTStatus.USER_SESSION_DELETED:
				self.session_closed = True
				raise SMBException('session delted', NTStatus.USER_SESSION_DELETED)
			
			
			else:
				raise SMBException('', rply.header.Status)
		
		except Exception as e:
			return None, e
		
	async def create(self, tree_id, file_path, desired_access, share_mode, create_options, create_disposition, file_attrs, impresonation_level = ImpersonationLevel.Impersonation, oplock_level = OplockLevel.SMB2_OPLOCK_LEVEL_NONE, create_contexts = None, return_reply = False):
		try:
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
					return rply.command.FileId, rply.command, None
				return rply.command.FileId, None
			
			elif rply.header.Status == NTStatus.ACCESS_DENIED:
				#this could mean incorrect filename/foldername OR actually access denied
				raise SMBCreateAccessDenied()
				
			else:
				raise SMBException('%s' % rply.header.Status.name, rply.header.Status)
		
		except Exception as e:
			if return_reply == True:
				return None, None, e
			return None, e
	
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

	async def ioctl(self, tree_id, file_id, ctlcode, data = None, flags = IOCTLREQFlags.IS_IOCTL):
		try:
			command = IOCTL_REQ()
			command.CtlCode  = ctlcode
			command.FileId  = file_id
			command.Flags = flags
			command.Buffer = data
			
			header = SMB2Header_SYNC()
			header.Command  = SMB2Command.IOCTL
			header.TreeId = tree_id
			
			msg = SMB2Message(header, command)
			message_id = await self.sendSMB(msg)

			rply = await self.recvSMB(message_id)

			return rply.command.Buffer, None

		except Exception as e:
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
		Use this function to properly terminate the SBM connection.
		Terminates the connection. Closes all tree handles, logs off and disconnects the TCP connection.
		"""
		#return
		try:		
			if self.session_closed == True or self.status == SMBConnectionStatus.CLOSED:
				return
			
			if self.status == SMBConnectionStatus.RUNNING:
				#only doing the proper disconnection if the connection was already running
				for tree_id in list(self.TreeConnectTable_id.keys()):
					try:
						await asyncio.wait_for(self.tree_disconnect(tree_id), timeout = 1)
					except:
						pass
				#logging off
				try:
					await asyncio.wait_for(self.logoff(), timeout = 1)
				except Exception as e:
					pass
			
			await asyncio.wait_for(self.disconnect(), timeout = 1)
			logger.debug('Terminate finished!')
		except asyncio.CancelledError:
			return
		except Exception as e:
			logger.debug('terminate error %s' % str(e))
	
	async def ghosting(self):
		#self.encryption_required = False
		self.supress_keepalive = True
		def compress_callback(msg):
			print('Callback is here!')
			msg_data = msg.to_bytes()
			compressed_data = lznt1_compress(msg_data)
			comp_hdr = SMB2Header_COMPRESSION_TRANSFORM()
			comp_hdr.OriginalCompressedSegmentSize = len(msg_data)
			comp_hdr.CompressionAlgorithm = SMB2CompressionType.LZNT1 #self.CompressionId
			comp_hdr.Flags = SMB2CompressionFlags.NONE
			comp_hdr.Offset = 0 #this should be marking the start of the compressed data

			return SMB2Compression(comp_hdr, compressed_data)

		print('################################### TESTING compression ###################################')
		await self.echo()
		#command = ECHO_REQ()
		#header = SMB2Header_SYNC()
		#header.Command  = SMB2Command.ECHO
		#msg = SMB2Message(header, command)
		#message_id = await self.sendSMB(msg)
		#print('Waiting for reply')
		#rply = await self.recvSMB(message_id)
		#print(rply)
		print('################################### SPLOIT SPLOIT SPLOIT ################################')

		
		command = ECHO_REQ()
		header = SMB2Header_SYNC()
		header.Command  = SMB2Command.ECHO
		msg = SMB2Message(header, command)
		message_id = await self.sendSMB(msg, compression_cb = compress_callback)
		try:
			rply = await asyncio.wait_for(self.recvSMB(message_id), timeout = 0.5)
			return True
		except:
			return False


#async def test(target):
#	#setting up NTLM auth
#	template_name = 'Windows10_15063_knowkey'
#	credential = Credential()
#	credential.username = 'victim'
#	credential.password = 'Passw0rd!1'
#	credential.domain = 'TEST'
#	
#	settings = NTLMHandlerSettings(credential, mode = 'CLIENT', template_name = template_name)
#	handler = NTLMAUTHHandler(settings)
#	
#	#setting up SPNEGO
#	spneg = SPNEGO()
#	spneg.add_auth_context('NTLMSSP - Microsoft NTLM Security Support Provider', handler)
#	connection = SMBConnection(spneg, [NegotiateDialects.SMB210])
#	await connection.connect(target)
#	await connection.negotiate()
#	await connection.session_setup()
#	tree_entry = await connection.tree_connect('\\\\10.10.10.2\\Users')
#	tree_id = tree_entry.tree_id
#	file_path = 'Administrator\\Desktop\\smb_test\\testfile1.txt'
#	
#	desired_access = FileAccessMask.FILE_READ_DATA
#	share_mode = ShareAccess.FILE_SHARE_READ
#	create_options = CreateOptions.FILE_NON_DIRECTORY_FILE
#	file_attrs = 0
#	create_disposition = CreateDisposition.FILE_OPEN
#	
#	file_id = await connection.create(tree_id, file_path, desired_access, share_mode, create_options, create_disposition, file_attrs)
#	
#	await connection.query_info(tree_id, file_id)
#	await connection.read(tree_id, file_id, offset = 0, length = 20)
#	
#	tree_entry = await connection.tree_connect('\\\\10.10.10.2\\Users')
#	tree_id = tree_entry.tree_id
#	file_path = 'Administrator\\Desktop\\smb_test\\'
#	
#	desired_access = FileAccessMask.FILE_READ_DATA
#	share_mode = ShareAccess.FILE_SHARE_READ
#	create_options = CreateOptions.FILE_DIRECTORY_FILE
#	file_attrs = 0
#	create_disposition = CreateDisposition.FILE_OPEN
#	
#	file_id = await connection.create(tree_id, file_path, desired_access, share_mode, create_options, create_disposition, file_attrs)
#	info = await connection.query_directory(tree_id, file_id)
#	print(str(info))
#	
#async def test_high(target):
#	#setting up NTLM auth
#	template_name = 'Windows10_15063_knowkey'
#	credential = Credential()
#	credential.username = 'victim'
#	credential.password = 'Passw0rd!1'
#	credential.domain = 'TEST'
#	
#	settings = NTLMHandlerSettings(credential, mode = 'CLIENT', template_name = template_name)
#	handler = NTLMAUTHHandler(settings)
#	
#	#setting up SPNEGO
#	spneg = SPNEGO()
#	spneg.add_auth_context('NTLMSSP - Microsoft NTLM Security Support Provider', handler)
#	connection = SMBConnection(spneg, [NegotiateDialects.SMB210])
#	await connection.connect(target)
#	await connection.negotiate()
#	await connection.session_setup()
#	
#	end = SMBEndpoint()
#	end.connection = connection
#	
#	await end.test()
#	
#async def test_kerberos(target):
#	settings = {
#		'mode' : 'CLIENT',
#		'connection_string' : 'TEST/victim/pass:Passw0rd!1@10.10.10.2',
#		'target_string': 'cifs/WIN2019AD@TEST.CORP',
#		'dc_ip' : '10.10.10.2',
#	}
#	
#	handler = SMBKerberos(settings)
#	
#	#setting up SPNEGO
#	spneg = SPNEGO()
#	spneg.add_auth_context('MS KRB5 - Microsoft Kerberos 5', handler)
#	connection = SMBConnection(spneg, [NegotiateDialects.SMB210])
#	await connection.connect(target)
#	await connection.negotiate()
#	await connection.session_setup()
#	tree_entry = await connection.tree_connect('\\\\10.10.10.2\\Users')
#	tree_id = tree_entry.tree_id
#	file_path = 'Administrator\\Desktop\\smb_test\\testfile1.txt'
#	
#	desired_access = FileAccessMask.FILE_READ_DATA
#	share_mode = ShareAccess.FILE_SHARE_READ
#	create_options = CreateOptions.FILE_NON_DIRECTORY_FILE
#	file_attrs = 0
#	create_disposition = CreateDisposition.FILE_OPEN
#	
#	file_id = await connection.create(tree_id, file_path, desired_access, share_mode, create_options, create_disposition, file_attrs)
#
#async def test_sspi_kerberos(target):
#	settings = {
#		'mode' : 'CLIENT',
#		'username' : None,
#		'password' : None,
#		'target' : 'WIN2019AD',
#	}
#	handler = SMBKerberosSSPI(settings)
#	#setting up SPNEGO
#	spneg = SPNEGO()
#	spneg.add_auth_context('MS KRB5 - Microsoft Kerberos 5', handler)
#	connection = SMBConnection(spneg, [NegotiateDialects.SMB210])
#	await connection.connect(target)
#	await connection.negotiate()
#	await connection.session_setup()
#	tree_entry = await connection.tree_connect('\\\\10.10.10.2\\Users')
#	tree_id = tree_entry.tree_id
#	file_path = 'Administrator\\Desktop\\smb_test\\testfile1.txt'
#	
#	desired_access = FileAccessMask.FILE_READ_DATA
#	share_mode = ShareAccess.FILE_SHARE_READ
#	create_options = CreateOptions.FILE_NON_DIRECTORY_FILE
#	file_attrs = 0
#	create_disposition = CreateDisposition.FILE_OPEN
#	
#	file_id = await connection.create(tree_id, file_path, desired_access, share_mode, create_options, create_disposition, file_attrs)
#	
#async def test_sspi_ntlm(target):
#	settings = {
#		'mode' : 'CLIENT',
#	}
#	handler = SMBNTLMSSPI(settings)
#	#setting up SPNEGO
#	spneg = SPNEGO()
#	spneg.add_auth_context('NTLMSSP - Microsoft NTLM Security Support Provider', handler)
#	connection = SMBConnection(spneg, [NegotiateDialects.SMB210])
#	await connection.connect(target)
#	await connection.negotiate()
#	await connection.session_setup()
#	tree_entry = await connection.tree_connect('\\\\10.10.10.2\\Users')
#	tree_id = tree_entry.tree_id
#	file_path = 'Administrator\\Desktop\\smb_test\\testfile1.txt'
#	
#	desired_access = FileAccessMask.FILE_READ_DATA
#	share_mode = ShareAccess.FILE_SHARE_READ
#	create_options = CreateOptions.FILE_NON_DIRECTORY_FILE
#	file_attrs = 0
#	create_disposition = CreateDisposition.FILE_OPEN
#	
#	file_id = await connection.create(tree_id, file_path, desired_access, share_mode, create_options, create_disposition, file_attrs)
#	
#	await connection.terminate()
#	
#async def connection_test(target):
#	#setting up NTLM auth
#	template_name = 'Windows10_15063_knowkey'
#	credential = Credential()
#	credential.username = 'victim'
#	credential.password = 'Passw0rd!1'
#	credential.domain = 'TEST'
#	
#	settings = NTLMHandlerSettings(credential, mode = 'CLIENT', template_name = template_name)
#	handler = NTLMAUTHHandler(settings)
#	
#	#setting up SPNEGO
#	spneg = SPNEGO()
#	spneg.add_auth_context('NTLMSSP - Microsoft NTLM Security Support Provider', handler)
#	connection = SMBConnection(spneg, [NegotiateDialects.SMB210])
#	await connection.connect(target)
#	await connection.negotiate()
#	await connection.session_setup()
#	#input(connection.get_extra_info())
#	tree_entry = await connection.tree_connect('\\\\10.10.10.2\\Users')
#	tree_id = tree_entry.tree_id
#	file_path = 'Administrator\\Desktop\\smb_test\\testfile1.txt'
#	
#	desired_access = FileAccessMask.FILE_READ_DATA
#	share_mode = ShareAccess.FILE_SHARE_READ
#	create_options = CreateOptions.FILE_NON_DIRECTORY_FILE
#	file_attrs = 0
#	create_disposition = CreateDisposition.FILE_OPEN
#	
#	file_id = await connection.create(tree_id, file_path, desired_access, share_mode, create_options, create_disposition, file_attrs)
#	
#	await connection.query_info(tree_id, file_id)
#	data, remaining = await connection.read(tree_id, file_id, offset = 100, length = 60000)
#	
#	print(data)
#	print(remaining)
#	
#	tree_entry = await connection.tree_connect('\\\\10.10.10.2\\Users')
#	tree_id = tree_entry.tree_id
#	file_path = 'Administrator\\Desktop\\smb_test\\'
#	
#	desired_access = FileAccessMask.FILE_READ_DATA
#	share_mode = ShareAccess.FILE_SHARE_READ
#	create_options = CreateOptions.FILE_DIRECTORY_FILE
#	file_attrs = 0
#	create_disposition = CreateDisposition.FILE_OPEN
#	
#	file_id = await connection.create(tree_id, file_path, desired_access, share_mode, create_options, create_disposition, file_attrs)
#	info = await connection.query_directory(tree_id, file_id)
#	await connection.terminate()
#	print(str(info))
#	
#async def filereader_test(target):
#	#setting up NTLM auth
#	template_name = 'Windows10_15063_knowkey'
#	credential = Credential()
#	credential.username = 'victim'
#	credential.password = 'Passw0rd!1'
#	credential.domain = 'TEST'
#	
#	settings = NTLMHandlerSettings(credential, mode = 'CLIENT', template_name = template_name)
#	handler = NTLMAUTHHandler(settings)
#	
#	#setting up SPNEGO
#	spneg = SPNEGO()
#	spneg.add_auth_context('NTLMSSP - Microsoft NTLM Security Support Provider', handler)
#	async with SMBConnection(spneg, target) as connection: 
#		await connection.login()
#		
#		async with SMBFileReader(connection) as reader:
#			await reader.open('\\\\10.10.10.2\\Users\\Administrator\\Desktop\\smb_test\\testfile1.txt')
#			data = await reader.read()
#			print(data)
#			await reader.seek(0,0)
#			data = await reader.read()
#			print(data)
#			await reader.seek(10,0)
#			data = await reader.read()
#			print(data)
#			await reader.seek(10,0)
#			data = await reader.read(5)
#			print(data)
#			await reader.seek(-10,2)
#			data = await reader.read(5)
#			print(data)
#	
#	
#			
#if __name__ == '__main__':
#	target = SMBTarget()
#	target.ip = '10.10.10.2'
#	target.port = 445
#	
#	target_bad = SMBTarget()
#	target_bad.ip = '10.10.10.66'
#	target_bad.port = 445
#
#	#asyncio.run(test(target))
#	#asyncio.run(test_kerberos(target))
#	#asyncio.run(test_sspi_kerberos(target))
#	#asyncio.run(test_sspi_ntlm(target))
#	#asyncio.run(connection_test(target))
#	#asyncio.run(test_high(target))
#	asyncio.run(filereader_test(target))
#
async def ctest(cu):
	conn = cu.get_connection()
	await conn.login()
	await conn.ghosting()
			
		


if __name__ == '__main__':
	from aiosmb.commons.connection.url import SMBConnectionURL

	logger.setLevel(2)
	#url = 'smb+ntlm-password://TEST\\victim:Passw0rd!1@10.10.10.2'
	url = 'smb222+ntlm-password://TEST\\victim:Passw0rd!1@10.10.10.2'
	#url = 'smb202+ntlm-password://work\\work:work@10.10.10.103'
	#url = 'smb+ntlm-password://smbtest\\smbtest:smbtest@10.200.200.154'
	cu = SMBConnectionURL(url)
	
	asyncio.run(ctest(cu))
	