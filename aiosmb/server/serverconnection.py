import enum
import io
import asyncio
import datetime
import hashlib
import hmac
import logging
import secrets
import typing
from dataclasses import dataclass, field
from pathlib import Path

from aiosmb import logger
from aiosmb.commons.exceptions import *
from aiosmb.protocol.smb.command_codes import SMBCommand
from aiosmb.wintypes.ntstatus import NTStatus
from aiosmb.protocol.smb.message import SMBMessage
from aiosmb.protocol.smb.commands import *
from aiosmb.protocol.smb2.message import SMB2Message
from aiosmb.protocol.smb2.commands.tree_connect import *
from aiosmb.protocol.smb2.commands import *
from aiosmb.protocol.smb2.headers import *
from aiosmb.protocol.smb2.command_codes import *
from aiosmb.protocol.common import *
from aiosmb.wintypes.dtyp.constrcuted_security.guid import *
from aiosmb.protocol.smb2.commands.sessionsetup import *
from aiosmb.protocol.smb2.commands.create import *
from aiosmb.protocol.smb2.commands.write import WriteFlag
from aiosmb.wintypes.fscc.FileAttributes import FileAttributes
from aiosmb.wintypes.fscc.structures.fileinfoclass import (
	FileInfoClass,
	FileSystemInfoClass,
)
from aiosmb.server.filesystem import (
	DirectoryEntry,
	FilesystemCleanupError,
	FilesystemObjectType,
	HandleTypeError,
	InvalidHandleError,
	InvalidPathError,
	LocalFilesystemBackend,
	ReadOnlyShareError,
	ShareNotFoundError,
)
from aiosmb.dcerpc.v5.servers.srvsvc import SRVSVCServer


TRACE_LEVEL = 5


def convert_to_ft(linux_filetime:int):
	return int((linux_filetime + 11644473600) * 10000000)


class SharingViolationError(PermissionError):
	pass


def status_from_exception(error):
	if isinstance(error, (InvalidHandleError,)):
		return NTStatus.INVALID_HANDLE
	if isinstance(error, SharingViolationError):
		return NTStatus.SHARING_VIOLATION
	if isinstance(error, (InvalidPathError, PermissionError, ReadOnlyShareError)):
		return NTStatus.ACCESS_DENIED
	if isinstance(error, ShareNotFoundError):
		return NTStatus.BAD_NETWORK_NAME
	if isinstance(error, FileNotFoundError):
		return NTStatus.OBJECT_NAME_NOT_FOUND
	if isinstance(error, FileExistsError):
		return NTStatus.OBJECT_NAME_COLLISION
	if isinstance(error, IsADirectoryError):
		return NTStatus.FILE_IS_A_DIRECTORY
	if isinstance(error, NotADirectoryError):
		return NTStatus.NOT_A_DIRECTORY
	if isinstance(error, OSError):
		return NTStatus.UNSUCCESSFUL
	if isinstance(error, (ValueError, TypeError)):
		return NTStatus.INVALID_PARAMETER
	return NTStatus.UNSUCCESSFUL

class SMBConnectionStatus(enum.Enum):
	NEGOTIATING = 'NEGOTIATING'
	SESSIONSETUP = 'SESSIONSETUP'
	RUNNING = 'RUNNING'
	CLOSED = 'CLOSED'

@dataclass
class FileEntry:
	file_id:int = None
	path:Path = None
	handle:io.FileIO = None


@dataclass
class PipeHandle:
	file_id:int
	name:str
	rpc_server:typing.Any
	output_buffer:bytearray = field(default_factory=bytearray)
	closed:bool = False

@dataclass
class TreeEntry:
	file_entries:typing.Dict[int, FileEntry] = field(default_factory=dict)
	hostname:str = None
	path:Path = None
	tree_id:int = None
	share:typing.Any = None
	is_pipe:bool = False

@dataclass
class DirEnumState:
	entries:typing.List[str] = field(default_factory=list)
	index:int = 0
	pattern:str = '*'
	info_class:FileInfoClass = None



class SMBServerConnection:
	def __init__(self, settings, connection, connection_id, shutdown_evt = None):
		self.settings = settings
		self.gssapi = self.settings.create_new_gssapi(connection)
		self.connection_id = connection_id
		
		#######DONT CHANGE THIS
		#use this for smb2 > self.supported_dialects = [NegotiateDialects.WILDCARD, NegotiateDialects.SMB202, NegotiateDialects.SMB210]
		#self.supported_dialects = [NegotiateDialects.SMB202, NegotiateDialects.SMB210]
		self.supported_dialects = self.settings.preferred_dialects #[NegotiateDialects.WILDCARD, NegotiateDialects.SMB311]
		#######
		
		self.connection = connection
		self.filesystem = (
			self.settings.create_filesystem_backend()
			if hasattr(self.settings, 'create_filesystem_backend')
			else LocalFilesystemBackend(self.settings.shares)
		)
		self.incoming_task = None
		self.shutdown_evt = shutdown_evt if shutdown_evt is not None else asyncio.Event()
		self._stopping = False
		self._compound_responses = None
		
		self.selected_dialect = None
		self.signing_required = self.settings.RequireSigning
		self.encryption_required = False
		self.last_treeid = 10
		
		self.status = SMBConnectionStatus.NEGOTIATING
		
		self.OutstandingResponsesEvent = {}
		self.OutstandingRequests = {}
		self.OutstandingResponses = {}

		self.pending_table = {}
		
		self.SequenceWindow = 0
		self.MaxTransactSize = self.settings.MaxTransactSize
		self.MaxReadSize = self.settings.MaxReadSize
		self.MaxWriteSize = self.settings.MaxWriteSize
		self.ServerGuid = self.settings.ServerGuid

		self.SupportsFileLeasing = False
		self.SupportsMultiCredit = False
		
		self.SupportsDirectoryLeasing = False
		self.SupportsMultiChannel = False
		self.SupportsPersistentHandles = False
		self.SupportsEncryption = False
		self.ClientCapabilities = 0
		self.ServerCapabilities = NegotiateCapabilities.LARGE_MTU #NegotiateCapabilities.DFS | NegotiateCapabilities.LARGE_MTU
		self.ClientSecurityMode = 0
		self.ServerSecurityMode = NegotiateSecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED
		if self.signing_required is True:
			self.ServerSecurityMode |= NegotiateSecurityMode.SMB2_NEGOTIATE_SIGNING_REQUIRED
		
		self.SessionId = 0
		self.SessionKey = None

		self.last_treeid = 1

		self.__treeid_to_entry = {}

	async def run(self):
		self.incoming_task = asyncio.create_task(self.__handle_smb_in())
		await asyncio.sleep(0)
		return self.incoming_task
	
	async def stop(self):
		if self._stopping:
			return
		self._stopping = True
		try:
			await self.print('[INF] Stopping connection')
			for tree in list(self.__treeid_to_entry.values()):
				for entry in list(tree.file_entries.values()):
					if isinstance(entry, PipeHandle):
						await self._close_pipe(entry)
						continue
					handle = getattr(entry, 'handle', None)
					if handle is not None and not getattr(handle, 'closed', False):
						try:
							handle.close()
						except Exception:
							pass
				tree.file_entries.clear()
			try:
				await self.filesystem.close_all()
			except FilesystemCleanupError as e:
				await self.print('[ERR] Filesystem cleanup: %s' % e)
			self.__treeid_to_entry.clear()
			self.status = SMBConnectionStatus.CLOSED
			self.shutdown_evt.set()
			current = asyncio.current_task()
			if self.incoming_task is not None and self.incoming_task is not current:
				self.incoming_task.cancel()
			if self.connection is not None:
				await self.connection.close()
		except Exception as e:
			await self.print('[ERR] %s' % e)

	async def log(self, level, msg):
		level_name = logging.getLevelName(level)
		await self.settings.emit_log(
			level,
			'[SMBSERVERCONN][%s][%s] %s'
			% (self.connection_id, level_name, msg),
		)

	async def print(self, msg):
		"""Compatibility adapter for older internal log call sites."""
		level = logging.INFO
		for prefix, mapped_level in (
			('[PACKET] ', TRACE_LEVEL),
			('[ERR] ', logging.ERROR),
			('[INF] ', logging.INFO),
			('[DEBUG] ', logging.DEBUG),
		):
			if msg.startswith(prefix):
				msg = msg[len(prefix):]
				level = mapped_level
				break
		await self.log(level, msg)

	@staticmethod
	def _share_name(tree):
		if tree.is_pipe:
			return 'IPC$'
		return getattr(tree.share, 'name', '<unknown>')

	@staticmethod
	def _handle_name(handle):
		if isinstance(handle, PipeHandle):
			return r'\PIPE\%s' % handle.name
		path = getattr(handle, 'relative_path', None)
		if path is None:
			path = getattr(handle, 'path', '<unknown>')
		return '\\' + str(path).replace('/', '\\').lstrip('\\')

	def get_new_tree_id(self):
		self.last_treeid += 1
		return self.last_treeid

	async def __handle_smb_in(self):
		"""
		Waits from SMB message bytes from the transport in_queue, and fills the connection table.
		This function started automatically when calling connect.
		Pls don't touch it.
		"""
		try:
			async for msg_data in self.connection.read():
				if msg_data is None:
					break
				
				if msg_data[0] < 252:
					raise Exception('Unknown SMB packet type %s' % msg_data[0])

				if msg_data[0] == 0xFD:
					raise Exception('SMB2_COMPRESSED_DATA_HEADER is not implemented yet')

				if msg_data[0] == 0xFC:
					raise Exception('SMB2_COMPRESSED_TRANSFORM_HEADER is not implemented yet')
					
				if msg_data[0] == 0xFE:
					await self._handle_smb2_packet(msg_data)
					continue
				if msg_data[0] == 0xFF:
					#version1
					msg = SMBMessage.from_bytes(msg_data)
					await self.print('[PACKET] %s' % msg)
					if self.status == SMBConnectionStatus.NEGOTIATING:
						if msg.header.Command == SMBCommand.SMB_COM_NEGOTIATE:
							await self.negotiate(msg)
					else:
						await self.log(
							logging.WARNING,
							'unexpected SMBv1 command %s' % msg.header.Command,
						)
						continue

				logger.log(1, '__handle_smb_in got new message with Id %s' % msg.header.MessageId)

				if msg.header.MessageId in self.pending_table:
					await self.pending_table[msg.header.MessageId].stop()
					del self.pending_table[msg.header.MessageId]
				
		except asyncio.CancelledError:
			return
		except Exception as e:
			await self.log(logging.ERROR, 'receive loop failed: %s' % e)
		finally:
			await self.stop()

	def _parse_compound(self, packet):
		if len(packet) < 64:
			return [(SMB2Message.from_bytes(packet), packet)]
		messages = []
		offset = 0
		inherited_tree_id = None
		inherited_session_id = None
		while offset < len(packet):
			if len(packet) - offset < 64:
				raise ValueError('Truncated SMB2 compound header')
			next_command = int.from_bytes(packet[offset + 20:offset + 24], 'little')
			if next_command:
				if next_command < 64 or next_command % 8 or offset + next_command > len(packet):
					raise ValueError('Invalid SMB2 NextCommand offset')
				end = offset + next_command
			else:
				end = len(packet)
			raw_message = packet[offset:end]
			message = SMB2Message.from_bytes(raw_message)
			if message.header.Flags & SMB2HeaderFlag.SMB2_FLAGS_RELATED_OPERATIONS:
				if inherited_tree_id is not None and message.header.TreeId == 0xFFFFFFFF:
					message.header.TreeId = inherited_tree_id
				if inherited_session_id is not None and message.header.SessionId == 0xFFFFFFFFFFFFFFFF:
					message.header.SessionId = inherited_session_id
			else:
				inherited_tree_id = message.header.TreeId
				inherited_session_id = message.header.SessionId
			messages.append((message, raw_message))
			if not next_command:
				break
			offset = end
		return messages

	def _serialize_compound(self, messages):
		encoded = []
		for index, message in enumerate(messages):
			message.header.Signature = b'\x00' * 16
			message.header.NextCommand = 0
			command_data = message.command.to_bytes()
			message_length = 64 + len(command_data)
			if index != len(messages) - 1:
				message.header.NextCommand = (message_length + 7) & ~7
			raw = message.header.to_bytes() + command_data
			if message.header.NextCommand:
				raw += b'\x00' * (message.header.NextCommand - len(raw))
			if message.header.Flags & SMB2HeaderFlag.SMB2_FLAGS_SIGNED:
				if not self.SessionKey:
					raise ValueError('Cannot sign an SMB2 compound response without a session key')
				signature = hmac.new(self.SessionKey, raw, hashlib.sha256).digest()[:16]
				raw = raw[:48] + signature + raw[64:]
				message.header.Signature = signature
			encoded.append(raw)
		return b''.join(encoded)

	async def _handle_smb2_packet(self, packet):
		try:
			parsed = self._parse_compound(packet)
		except Exception as e:
			await self.print('[ERR] Failed to parse SMB2 packet: %s' % e)
			return

		self._compound_responses = []
		try:
			for message, raw_message in parsed:
				await self.print('[PACKET] %s' % message)
				if self.status == SMBConnectionStatus.RUNNING:
					is_signed = bool(message.header.Flags & SMB2HeaderFlag.SMB2_FLAGS_SIGNED)
					if self.signing_required and not is_signed:
						await self.send_error(message, NTStatus.ACCESS_DENIED)
						continue
					if is_signed:
						try:
							self.verify_message(message, raw_message)
						except Exception as e:
							await self.print('[ERR] %s' % e)
							await self.send_error(message, NTStatus.ACCESS_DENIED)
							continue
				await self._dispatch_smb2(message)
				if message.header.MessageId in self.pending_table:
					await self.pending_table.pop(message.header.MessageId).stop()
			if self._compound_responses:
				await self.connection.write(self._serialize_compound(self._compound_responses))
		finally:
			self._compound_responses = None

	async def _dispatch_smb2(self, msg):
		try:
			if self.status == SMBConnectionStatus.NEGOTIATING:
				if msg.header.Command != SMB2Command.NEGOTIATE:
					await self.send_error(msg, NTStatus.INVALID_PARAMETER)
					return
				await self.negotiate(msg)
				return
			if self.status == SMBConnectionStatus.SESSIONSETUP:
				if msg.header.Command != SMB2Command.SESSION_SETUP:
					await self.send_error(msg, NTStatus.ACCESS_DENIED)
					return
				await self.session_setup(msg)
				return
			if self.status != SMBConnectionStatus.RUNNING:
				return
			handler = {
				SMB2Command.TREE_CONNECT: self.tree_connect,
				SMB2Command.CREATE: self.create,
				SMB2Command.READ: self.read,
				SMB2Command.WRITE: self.write,
				SMB2Command.FLUSH: self.flush,
				SMB2Command.IOCTL: self.ioctl,
				SMB2Command.ECHO: self.echo,
				SMB2Command.QUERY_INFO: self.query_info,
				SMB2Command.QUERY_DIRECTORY: self.query_directory,
				SMB2Command.SET_INFO: self.set_info,
				SMB2Command.CLOSE: self.close,
				SMB2Command.TREE_DISCONNECT: self.tree_disconnect,
				SMB2Command.LOGOFF: self.logoff,
			}.get(msg.header.Command)
			if handler is None:
				await self.send_error(msg, NTStatus.NOT_SUPPORTED)
				return
			await handler(msg)
		except Exception as e:
			await self.print('[ERR] Command %s failed: %s' % (msg.header.Command, e))
			await self.send_error(msg, NTStatus.UNSUCCESSFUL)

	async def send_error(self, originator, status):
		level = (
			logging.DEBUG
			if status in (
				NTStatus.END_OF_FILE,
				NTStatus.NO_MORE_FILES,
				NTStatus.PIPE_EMPTY,
			)
			else logging.WARNING
		)
		await self.log(
			level,
			'command=%s status=%s'
			% (originator.header.Command, status),
		)
		error = ERROR_REPLY()
		await self.sendSMB2(originator, originator.header.Command, error, status)
	
	def sign_message(self, msg):
		if self.selected_dialect != NegotiateDialects.SMB202:
			raise ValueError('Only SMB 2.0.2 signing is supported by this server')
		if not self.SessionKey:
			raise ValueError('Cannot sign an SMB2 message without a session key')
		msg.header.Flags |= SMB2HeaderFlag.SMB2_FLAGS_SIGNED
		msg.header.Signature = b'\x00' * 16
		msg.header.Signature = hmac.new(
			self.SessionKey,
			msg.to_bytes(),
			hashlib.sha256,
		).digest()[:16]

	def verify_message(self, msg, msg_data):
		if self.selected_dialect != NegotiateDialects.SMB202:
			raise ValueError('Only SMB 2.0.2 signing is supported by this server')
		if not self.SessionKey:
			raise ValueError('Cannot verify an SMB2 message without a session key')
		if len(msg_data) < 64:
			raise ValueError('Signed SMB2 message is shorter than its fixed header')
		unsigned_data = bytearray(msg_data)
		signature = bytes(unsigned_data[48:64])
		unsigned_data[48:64] = b'\x00' * 16
		expected = hmac.new(
			self.SessionKey,
			bytes(unsigned_data),
			hashlib.sha256,
		).digest()[:16]
		if not secrets.compare_digest(signature, expected):
			raise ValueError('SMB2 signature verification failed')
		return True

	async def sendSMB(self, msg, compression_cb = None):
		"""
		Sends an SMB message to teh remote endpoint.
		msg: SMB2Message or SMBMessage
		Returns: MessageId integer
		"""
		try:
			if isinstance(msg, SMBMessage):
				await self.connection.write(msg.to_bytes())
				return 0, msg, None

			if msg.header.MessageId is None:
				msg.header.MessageId = self.SequenceWindow
				self.SequenceWindow += 1
			if msg.header.SessionId == 0 and self.status != SMBConnectionStatus.NEGOTIATING:
				msg.header.SessionId = self.SessionId
			if not msg.header.CreditCharge:
				msg.header.CreditCharge = 1
			if msg.header.CreditReq is None:
				msg.header.CreditReq = 1
			msg.header.CreditReq = max(
				1,
				min(int(msg.header.CreditReq), getattr(self.settings, 'MaxCredits', 128)),
			)
			if self._compound_responses is not None:
				self._compound_responses.append(msg)
				return msg.header.MessageId, msg, None
			if msg.header.Flags & SMB2HeaderFlag.SMB2_FLAGS_SIGNED:
				self.sign_message(msg)
			message_id = msg.header.MessageId
			await self.connection.write(msg.to_bytes())
			
			return message_id, msg, None
		except Exception as e:
			await self.log(logging.ERROR, 'send failed: %s' % e)
			return None, None, e
		
	async def negotiate(self, req):
		try:
			if (isinstance(req, SMBMessage) and 'SMB 2.???' in req.command.Dialects) or isinstance(req, SMB2Message):
					await self.log(
						logging.DEBUG,
						'negotiating SMB 2.0.2 signing=%s ess=%s'
						% (
							'required' if self.signing_required else 'optional',
							'disabled'
							if getattr(self.settings, 'DisableESS', False)
							else 'client-negotiated',
						),
					)
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
					if isinstance(req, SMB2Message):
						await self.sendSMB2(req, SMB2Command.NEGOTIATE, reply.command, NTStatus.SUCCESS)
					else:
						reply.header.MessageId = 0
						await self.sendSMB(reply)

					self.selected_dialect = NegotiateDialects.SMB202

					
					self.SupportsMultiChannel = NegotiateCapabilities.MULTI_CHANNEL in self.ServerCapabilities
					self.SupportsFileLeasing = NegotiateCapabilities.LEASING in self.ServerCapabilities
					self.SupportsMultiCredit = NegotiateCapabilities.LARGE_MTU in self.ServerCapabilities
					
					self.status = (
						SMBConnectionStatus.SESSIONSETUP
						if isinstance(req, SMB2Message)
						else SMBConnectionStatus.NEGOTIATING
					)
			return
		except Exception as e:
			await self.log(logging.ERROR, 'negotiate failed: %s' % e)

	async def session_setup(self, msg):
		reply = SESSION_SETUP_REPLY()
		reply.SessionFlags = 0
		try:
			if self.SessionId == 0:
				self.SessionId = 1
			await self.log(logging.DEBUG, 'processing session authentication')
			reply.Buffer, to_continue, err = await self.gssapi.authenticate_server(msg.command.Buffer)
			await self.log(
				logging.DEBUG,
				'authentication step complete continue=%s error=%s'
				% (to_continue, type(err).__name__ if err else 'none'),
			)
			if err is not None:
				raise err
			if to_continue:
				await self.sendSMB2(
					msg,
					SMB2Command.SESSION_SETUP,
					reply,
					NTStatus.MORE_PROCESSING_REQUIRED,
				)
				return True, None

			if reply.Buffer is None:
				reply.Buffer, err = await self.gssapi.authenticate_server_finished()
				if err is not None:
					raise err

			is_anonymous = bool(
				hasattr(self.gssapi, 'is_anonymous')
				and self.gssapi.is_anonymous()
			)
			if is_anonymous and self.signing_required:
				raise PermissionError(
					'Anonymous sessions cannot satisfy required SMB signing'
				)
			session_key = self.gssapi.get_session_key()
			if is_anonymous:
				self.SessionKey = None
				reply.SessionFlags = SessionFlags.SMB2_SESSION_FLAG_IS_NULL
				identity = 'anonymous'
			else:
				self.SessionKey = session_key[:16] if session_key else None
				if self.SessionKey is None:
					reply.SessionFlags = SessionFlags.SMB2_SESSION_FLAG_IS_GUEST
					identity = 'guest'
				else:
					username = getattr(
						self.gssapi,
						'_authenticated_username',
						'authenticated user',
					)
					domain = getattr(
						self.gssapi,
						'_authenticated_domain',
						'',
					)
					identity = (
						'%s\\%s' % (domain, username)
						if domain else str(username)
					)
			self.status = SMBConnectionStatus.RUNNING
			await self.log(
				logging.INFO,
				'session established identity=%r signing=%s'
				% (
					identity,
					'enabled' if self.signing_required else 'disabled',
				),
			)
			ntlm_hash = (
				self.gssapi.get_ntlm_hash()
				if hasattr(self.gssapi, 'get_ntlm_hash')
				else None
			)
			if ntlm_hash:
				await self.log(
					logging.INFO,
					'NetNTLMv2 hash=%s' % ntlm_hash,
				)
			await self.sendSMB2(msg, SMB2Command.SESSION_SETUP, reply, NTStatus.SUCCESS)
			return False, None
		except Exception as e:
			await self.print('[ERR] %s' % e)
			reply.Buffer = b''
			await self.sendSMB2(msg, SMB2Command.SESSION_SETUP, reply, NTStatus.ACCESS_DENIED)
			return False, e


	async def tree_connect(self, msg:SMB2Message):
		try:
			command = typing.cast(TREE_CONNECT_REQ, msg.command)
			reply = SMB2Message()
			reply.header = SMB2Header_SYNC()
			reply.header.Command = SMB2Command.TREE_CONNECT
			reply.header.Flags = SMB2HeaderFlag.SMB2_FLAGS_SERVER_TO_REDIR
			reply.header.SessionId = self.SessionId
			reply.header.CreditCharge = 1
			reply.header.CreditReq = msg.header.CreditReq
			reply.header.Status = NTStatus.SUCCESS
			reply.command = TREE_CONNECT_REPLY()
			reply.command.ShareFlags = ShareFlags.SMB2_SHAREFLAG_MANUAL_CACHING
			reply.command.Capabilities = TreeCapabilities.SMB2_SHARE_CAP_NONE
			reply.command.MaximalAccess = FileAccessMask.GENERIC_ALL
			parts = [part for part in command.Path.split('\\') if part]
			if len(parts) < 2:
				await self.send_error(msg, NTStatus.BAD_NETWORK_NAME)
				return
			share_name = parts[-1]
			is_pipe = share_name.casefold() == 'ipc$'
			await self.log(
				logging.INFO,
				'connect share=%r type=%s'
				% (share_name, 'pipe' if is_pipe else 'disk'),
			)
			share = None
			mapped = None
			if is_pipe:
				reply.command.ShareType = ShareType.PIPE
				reply.command.MaximalAccess = FileAccessMask.GENERIC_READ | FileAccessMask.GENERIC_WRITE
			else:
				reply.command.ShareType = ShareType.DISK
				try:
					share = self.filesystem.get_share(share_name)
				except ShareNotFoundError:
					await self.sendSMB2(
						msg,
						SMB2Command.TREE_CONNECT,
						reply.command,
						NTStatus.BAD_NETWORK_NAME,
					)
					return
				mapped = share.root
				reply.command.MaximalAccess = (
					FileAccessMask.GENERIC_READ
					if share.read_only
					else FileAccessMask.GENERIC_ALL
				)

			tree_id = self.get_new_tree_id()
			reply.header.TreeId = tree_id
			self.__treeid_to_entry[tree_id] = TreeEntry(
				hostname=parts[-2],
				path=mapped,
				tree_id=tree_id,
				share=share,
				is_pipe=is_pipe,
			)

			await self.sendSMB2(
				msg,
				SMB2Command.TREE_CONNECT,
				reply.command,
				NTStatus.SUCCESS,
				tree_id=tree_id,
			)
		except Exception as e:
			await self.log(logging.ERROR, 'share connect failed: %s' % e)
			await self.send_error(msg, NTStatus.UNSUCCESSFUL)
	
	async def ioctl(self, msg:SMB2Message):
		try:
			command = typing.cast(IOCTL_REQ, msg.command)
			await self.log(
				logging.DEBUG,
				'ioctl control=%s tree_id=%s'
				% (command.CtlCode, msg.header.TreeId),
			)
			if command.CtlCode == CtlCode.FSCTL_DFS_GET_REFERRALS:
				await self.send_error(msg, NTStatus.FS_DRIVER_REQUIRED)
				return
			if command.CtlCode == CtlCode.FSCTL_PIPE_WAIT:
				reply = self._ioctl_reply(command, b'')
				await self.sendSMB2(msg, SMB2Command.IOCTL, reply, NTStatus.SUCCESS)
				return
			if command.CtlCode not in (
				CtlCode.FSCTL_PIPE_PEEK,
				CtlCode.FSCTL_PIPE_TRANSCEIVE,
			):
				await self.send_error(msg, NTStatus.NOT_SUPPORTED)
				return
			tree, handle = self._lookup_handle(
				msg.header.TreeId,
				command.FileId,
			)
			if not tree.is_pipe or not isinstance(handle, PipeHandle):
				await self.send_error(msg, NTStatus.INVALID_DEVICE_REQUEST)
				return
			if command.CtlCode == CtlCode.FSCTL_PIPE_TRANSCEIVE:
				responses = await handle.rpc_server.feed_data(command.Buffer or b'')
				for response in responses:
					handle.output_buffer.extend(response)
				maximum = command.MaxOutputResponse or 65536
				data = bytes(handle.output_buffer[:maximum])
				del handle.output_buffer[:maximum]
			else:
				available = len(handle.output_buffer)
				maximum = max(0, (command.MaxOutputResponse or 65536) - 16)
				peeked = bytes(handle.output_buffer[:maximum])
				data = (
					(3).to_bytes(4, 'little')
					+ available.to_bytes(4, 'little')
					+ (1 if available else 0).to_bytes(4, 'little')
					+ available.to_bytes(4, 'little')
					+ peeked
				)
			reply = self._ioctl_reply(command, data)
			await self.sendSMB2(msg, SMB2Command.IOCTL, reply, NTStatus.SUCCESS)
		except Exception as e:
			await self.send_error(msg, status_from_exception(e))

	def _ioctl_reply(self, command, data):
		reply = IOCTL_REPLY()
		reply.CtlCode = command.CtlCode
		reply.FileId = command.FileId
		reply.InputOffset = 0
		reply.InputCount = 0
		reply.OutputOffset = 112 if data else 0
		reply.OutputCount = len(data)
		reply.Flags = command.Flags
		reply.Buffer = data
		return reply
		
	async def create(self, msg:SMB2Message):
		try:
			command = typing.cast(CREATE_REQ, msg.command)
			te = self.__treeid_to_entry.get(msg.header.TreeId)
			if te is None:
				await self.send_error(msg, NTStatus.NETWORK_NAME_DELETED)
				return
			if te.is_pipe:
				await self._create_pipe(msg, te, command)
				return

			path = command.Name or ''
			if path in ('\\', '/'):
				path = ''
			options = command.CreateOptions or CreateOptions(0)
			disposition = command.CreateDisposition or CreateDisposition.FILE_OPEN
			is_directory = (
				not path
				or bool(options & CreateOptions.FILE_DIRECTORY_FILE)
			)
			if (
				options & CreateOptions.FILE_DIRECTORY_FILE
				and options & CreateOptions.FILE_NON_DIRECTORY_FILE
			):
				await self.send_error(msg, NTStatus.INVALID_PARAMETER)
				return

			try:
				existing_stat = await self.filesystem.stat(te.share, path)
				exists = True
			except FileNotFoundError:
				existing_stat = None
				exists = False

			if disposition == CreateDisposition.FILE_OPEN and not exists:
				raise FileNotFoundError(path)
			if disposition == CreateDisposition.FILE_CREATE and exists:
				raise FileExistsError(path)
			if disposition == CreateDisposition.FILE_OVERWRITE and not exists:
				raise FileNotFoundError(path)
			if is_directory and disposition in (
				CreateDisposition.FILE_OVERWRITE,
				CreateDisposition.FILE_OVERWRITE_IF,
				CreateDisposition.FILE_SUPERSEDE,
			):
				await self.send_error(msg, NTStatus.INVALID_PARAMETER)
				return

			created = not exists
			overwritten = exists and disposition in (
				CreateDisposition.FILE_OVERWRITE,
				CreateDisposition.FILE_OVERWRITE_IF,
				CreateDisposition.FILE_SUPERSEDE,
			)
			object_type = (
				FilesystemObjectType.DIRECTORY
				if is_directory
				else FilesystemObjectType.FILE
			)
			desired_access = int(command.DesiredAccess or 0)
			wants_write = bool(
				desired_access
				& int(
					FileAccessMask.FILE_WRITE_DATA
					| FileAccessMask.FILE_APPEND_DATA
					| FileAccessMask.GENERIC_WRITE
					| FileAccessMask.GENERIC_ALL
				)
			)
			if is_directory:
				intent = 'create directory' if created else 'open directory'
			elif created:
				intent = 'create file'
			elif overwritten:
				intent = 'overwrite file'
			elif wants_write:
				intent = 'open file for write'
			else:
				intent = 'open file for read'
			await self.log(
				logging.INFO,
				"%s share=%s path=%r"
				% (intent, self._share_name(te), path or '\\'),
			)
			if created and is_directory:
				await self.filesystem.mkdir(te.share, path)

			if is_directory:
				mode = 'rb'
			elif created:
				mode = 'x+b'
			elif overwritten:
				mode = 'w+b'
			elif wants_write:
				mode = 'r+b'
			else:
				mode = 'rb'
			local_path = await self.filesystem.resolve_path(te.share, path)
			self._check_share_access(
				local_path,
				desired_access,
				int(command.ShareAccess or 0),
			)

			handle = await self.filesystem.open(
				te.share,
				path,
				mode=mode,
				desired_access=desired_access,
				share_access=int(command.ShareAccess or 0),
				create_options=int(options),
				delete_on_close=bool(options & CreateOptions.FILE_DELETE_ON_CLOSE),
				object_type=object_type,
				session_id=self.SessionId,
				tree_id=te.tree_id,
			)
			te.file_entries[handle.file_id] = handle
			fstat = await self.filesystem.stat_handle(handle)

			reply = CREATE_REPLY()
			reply.OplockLevel = OplockLevel.SMB2_OPLOCK_LEVEL_NONE
			reply.Flags = CreateReplyFlag.NONE
			if created:
				reply.CreateAction = CreateAction.FILE_CREATED
			elif overwritten:
				reply.CreateAction = CreateAction.FILE_OVERWRITTEN
			else:
				reply.CreateAction = CreateAction.FILE_OPENED
			reply.CreationTime = convert_to_ft(fstat.st_ctime)
			reply.LastAccessTime = convert_to_ft(fstat.st_atime)
			reply.LastWriteTime = convert_to_ft(fstat.st_mtime)
			reply.ChangeTime = convert_to_ft(fstat.st_mtime)
			reply.AllocationSize = int(getattr(fstat, 'st_blocks', 0) * 512)
			reply.EndofFile = 0 if is_directory else fstat.st_size
			reply.FileAttributes = (
				FileAttributes.FILE_ATTRIBUTE_DIRECTORY
				if is_directory
				else FileAttributes.FILE_ATTRIBUTE_NORMAL
			)
			reply.FileId = handle.file_id
			reply.CreateContext = []
			await self.sendSMB2(msg, SMB2Command.CREATE, reply, NTStatus.SUCCESS)
		except Exception as e:
			await self.log(
				logging.ERROR,
				'open failed tree_id=%s path=%r: %s'
				% (
					msg.header.TreeId,
					getattr(msg.command, 'Name', ''),
					e,
				),
			)
			await self.send_error(msg, status_from_exception(e))

	@staticmethod
	def _access_categories(access):
		access = int(access)
		read = bool(
			access & int(
				FileAccessMask.FILE_READ_DATA
				| FileAccessMask.FILE_READ_EA
				| FileAccessMask.FILE_READ_ATTRIBUTES
				| FileAccessMask.GENERIC_READ
				| FileAccessMask.GENERIC_ALL
			)
		)
		write = bool(
			access & int(
				FileAccessMask.FILE_WRITE_DATA
				| FileAccessMask.FILE_APPEND_DATA
				| FileAccessMask.FILE_WRITE_EA
				| FileAccessMask.FILE_WRITE_ATTRIBUTES
				| FileAccessMask.GENERIC_WRITE
				| FileAccessMask.GENERIC_ALL
			)
		)
		delete = bool(
			access & int(FileAccessMask.DELETE | FileAccessMask.GENERIC_ALL)
		)
		return read, write, delete

	def _check_share_access(self, local_path, desired_access, share_access):
		new_read, new_write, new_delete = self._access_categories(desired_access)
		for tree in self.__treeid_to_entry.values():
			if tree.is_pipe:
				continue
			for existing in tree.file_entries.values():
				if getattr(existing, 'local_path', None) != local_path:
					continue
				existing_share = int(existing.share_access)
				if new_read and not existing_share & int(ShareAccess.FILE_SHARE_READ):
					raise SharingViolationError('read sharing violation')
				if new_write and not existing_share & int(ShareAccess.FILE_SHARE_WRITE):
					raise SharingViolationError('write sharing violation')
				if new_delete and not existing_share & int(ShareAccess.FILE_SHARE_DELETE):
					raise SharingViolationError('delete sharing violation')
				old_read, old_write, old_delete = self._access_categories(
					existing.desired_access
				)
				if old_read and not share_access & int(ShareAccess.FILE_SHARE_READ):
					raise SharingViolationError('read sharing violation')
				if old_write and not share_access & int(ShareAccess.FILE_SHARE_WRITE):
					raise SharingViolationError('write sharing violation')
				if old_delete and not share_access & int(ShareAccess.FILE_SHARE_DELETE):
					raise SharingViolationError('delete sharing violation')

	def _share_provider(self):
		result = {}
		for name, share in self.filesystem.shares.items():
			result[name] = {
				'name': name,
				'path': str(share.root),
				'remark': share.remark,
			}
		return result

	async def _create_pipe(self, msg, tree, command):
		name = (command.Name or '').replace('/', '\\').strip('\\')
		if name.casefold().startswith('pipe\\'):
			name = name[5:]
		await self.log(
			logging.INFO,
			'open named pipe share=IPC$ path=%r' % (r'\PIPE\%s' % name),
		)
		if name.casefold() != 'srvsvc':
			await self.send_error(msg, NTStatus.OBJECT_NAME_NOT_FOUND)
			return
		file_id = secrets.randbits(128) or 1
		rpc_server = SRVSVCServer(
			share_provider=self._share_provider,
			server_name=getattr(self.settings, 'ServerName', 'AIOSMB'),
			server_comment=getattr(
				self.settings,
				'ServerComment',
				'aiosmb SMB server',
			),
		)
		handle = PipeHandle(file_id, 'srvsvc', rpc_server)
		tree.file_entries[file_id] = handle
		now = convert_to_ft(datetime.datetime.now().timestamp())
		reply = CREATE_REPLY()
		reply.OplockLevel = OplockLevel.SMB2_OPLOCK_LEVEL_NONE
		reply.Flags = CreateReplyFlag.NONE
		reply.CreateAction = CreateAction.FILE_OPENED
		reply.CreationTime = now
		reply.LastAccessTime = now
		reply.LastWriteTime = now
		reply.ChangeTime = now
		reply.AllocationSize = 0
		reply.EndofFile = 0
		reply.FileAttributes = FileAttributes.FILE_ATTRIBUTE_NORMAL
		reply.FileId = file_id
		await self.sendSMB2(msg, SMB2Command.CREATE, reply, NTStatus.SUCCESS)

	async def _write_pipe(self, msg, handle, data):
		if handle.closed:
			raise InvalidHandleError('named pipe is closed')
		responses = await handle.rpc_server.feed_data(data)
		for response in responses:
			handle.output_buffer.extend(response)
		reply = WRITE_REPLY()
		reply.Count = len(data)
		await self.sendSMB2(msg, SMB2Command.WRITE, reply, NTStatus.SUCCESS)

	async def _read_pipe(self, msg, handle, command):
		if handle.closed:
			raise InvalidHandleError('named pipe is closed')
		if not handle.output_buffer:
			await self.send_error(msg, NTStatus.PIPE_EMPTY)
			return
		length = min(int(command.Length), self.MaxReadSize, 65536)
		data = bytes(handle.output_buffer[:length])
		del handle.output_buffer[:length]
		reply = READ_REPLY()
		reply.Buffer = data
		reply.DataRemaining = len(handle.output_buffer)
		await self.sendSMB2(msg, SMB2Command.READ, reply, NTStatus.SUCCESS)

	async def _close_pipe(self, handle):
		if handle.closed:
			return
		handle.closed = True
		handle.output_buffer.clear()
		await handle.rpc_server.close()

	def _lookup_handle(self, tree_id, file_id):
		tree = self.__treeid_to_entry.get(tree_id)
		if tree is None:
			raise InvalidHandleError('unknown tree ID')
		try:
			return tree, tree.file_entries[file_id]
		except KeyError:
			raise InvalidHandleError('unknown file ID')

	async def read(self, msg:SMB2Message):
		try:
			command = typing.cast(READ_REQ, msg.command)
			tree, handle = self._lookup_handle(msg.header.TreeId, command.FileId)
			await self.log(
				logging.DEBUG,
				'read share=%s path=%r offset=%s length=%s'
				% (
					self._share_name(tree),
					self._handle_name(handle),
					command.Offset,
					command.Length,
				),
			)
			if tree.is_pipe:
				await self._read_pipe(msg, handle, command)
				return
			if not self._access_categories(handle.desired_access)[0]:
				raise PermissionError('handle does not grant read access')
			length = min(int(command.Length), self.MaxReadSize, 65536)
			data = await self.filesystem.read(handle, int(command.Offset), length)
			if not data and length:
				await self.send_error(msg, NTStatus.END_OF_FILE)
				return
			fstat = await self.filesystem.stat_handle(handle)
			reply = READ_REPLY()
			reply.Buffer = data
			reply.DataRemaining = max(
				0,
				fstat.st_size - int(command.Offset) - len(data),
			)
			await self.sendSMB2(msg, SMB2Command.READ, reply, NTStatus.SUCCESS)
		except Exception as e:
			await self.send_error(msg, status_from_exception(e))

	async def write(self, msg:SMB2Message):
		try:
			command = typing.cast(WRITE_REQ, msg.command)
			tree, handle = self._lookup_handle(msg.header.TreeId, command.FileId)
			data = bytes(command.Data or b'')[:min(self.MaxWriteSize, 65536)]
			await self.log(
				logging.DEBUG,
				'write share=%s path=%r offset=%s length=%s'
				% (
					self._share_name(tree),
					self._handle_name(handle),
					command.Offset,
					len(data),
				),
			)
			if tree.is_pipe:
				await self._write_pipe(msg, handle, data)
				return
			if not self._access_categories(handle.desired_access)[1]:
				raise PermissionError('handle does not grant write access')
			count = await self.filesystem.write(handle, int(command.Offset), data)
			if command.Flags & WriteFlag.WRITE_THROUGH:
				await self.filesystem.flush(handle)
			reply = WRITE_REPLY()
			reply.Count = count
			reply.Remaining = max(0, len(command.Data or b'') - count)
			await self.sendSMB2(msg, SMB2Command.WRITE, reply, NTStatus.SUCCESS)
		except Exception as e:
			await self.send_error(msg, status_from_exception(e))

	async def flush(self, msg:SMB2Message):
		try:
			command = typing.cast(FLUSH_REQ, msg.command)
			tree, handle = self._lookup_handle(msg.header.TreeId, command.FileId)
			await self.log(
				logging.DEBUG,
				'flush share=%s path=%r'
				% (self._share_name(tree), self._handle_name(handle)),
			)
			if not tree.is_pipe:
				await self.filesystem.flush(handle)
			await self.sendSMB2(
				msg,
				SMB2Command.FLUSH,
				FLUSH_REPLY(),
				NTStatus.SUCCESS,
			)
		except Exception as e:
			await self.send_error(msg, status_from_exception(e))

	async def query_info(self, msg:SMB2Message):
		try:
			command = typing.cast(QUERY_INFO_REQ, msg.command)
			tree, handle = self._lookup_handle(msg.header.TreeId, command.FileId)
			await self.log(
				logging.DEBUG,
				'query info share=%s path=%r type=%s class=%s'
				% (
					self._share_name(tree),
					self._handle_name(handle),
					command.InfoType,
					command.FileInfoClass,
				),
			)
			if tree.is_pipe:
				await self.send_error(msg, NTStatus.NOT_SUPPORTED)
				return
			stat_result = await self.filesystem.stat_handle(handle)
			if command.InfoType == QueryInfoType.FILE:
				data = self._file_info_bytes(
					handle,
					stat_result,
					command.FileInfoClass,
				)
			elif command.InfoType == QueryInfoType.FILESYSTEM:
				data = await self._filesystem_info_bytes(
					tree,
					command.FileInfoClass,
				)
			else:
				await self.send_error(msg, NTStatus.NOT_SUPPORTED)
				return
			if len(data) > command.OutputBufferLength:
				await self.send_error(msg, NTStatus.BUFFER_TOO_SMALL)
				return
			reply = QUERY_INFO_REPLY()
			reply.Data = data
			await self.sendSMB2(
				msg,
				SMB2Command.QUERY_INFO,
				reply,
				NTStatus.SUCCESS,
			)
		except Exception as e:
			await self.send_error(msg, status_from_exception(e))

	def _file_info_bytes(self, handle, stat_result, info_class):
		from aiosmb.wintypes.fscc.structures.FileAllInformation import (
			FileAccessInformation,
			FileAlignmentInformation,
			FileAllInformation,
			FileModeInformation,
			FileNameInformation,
			FilePositionInformation,
		)
		from aiosmb.wintypes.fscc.structures.FileBasicInformation import (
			FileBasicInformation,
		)
		from aiosmb.wintypes.fscc.structures.FileEaInformation import (
			FileEaInformation,
		)
		from aiosmb.wintypes.fscc.structures.FileInternalInformation import (
			FileInternalInformation,
		)
		from aiosmb.wintypes.fscc.structures.FileNetworkOpenInformation import (
			FileNetworkOpenInformation,
		)
		from aiosmb.wintypes.fscc.structures.FileStandardInformation import (
			FileStandardInformation,
		)

		is_directory = handle.object_type is FilesystemObjectType.DIRECTORY
		attributes = (
			FileAttributes.FILE_ATTRIBUTE_DIRECTORY
			if is_directory
			else FileAttributes.FILE_ATTRIBUTE_NORMAL
		)
		allocation_size = (
			0 if is_directory else int(getattr(stat_result, 'st_blocks', 0) * 512)
		)
		end_of_file = 0 if is_directory else stat_result.st_size

		basic = FileBasicInformation()
		basic.CreationTime = convert_to_ft(stat_result.st_ctime)
		basic.LastAccessTime = convert_to_ft(stat_result.st_atime)
		basic.LastWriteTime = convert_to_ft(stat_result.st_mtime)
		basic.ChangeTime = convert_to_ft(stat_result.st_mtime)
		basic.FileAttributes = attributes

		standard = FileStandardInformation()
		standard.AllocationSize = allocation_size
		standard.EndOfFile = end_of_file
		standard.NumberOfLinks = int(getattr(stat_result, 'st_nlink', 1))
		standard.DeletePending = bool(handle.delete_on_close)
		standard.Directory = is_directory

		internal = FileInternalInformation()
		internal.IndexNumber = int(getattr(stat_result, 'st_ino', 0))
		ea = FileEaInformation()
		network = FileNetworkOpenInformation()
		network.CreationTime = basic.CreationTime
		network.LastAccessTime = basic.LastAccessTime
		network.LastWriteTime = basic.LastWriteTime
		network.ChangeTime = basic.ChangeTime
		network.AllocationSize = allocation_size
		network.EndOfFile = end_of_file
		network.FileAttributes = attributes

		if info_class == FileInfoClass.FileBasicInformation:
			return basic.to_bytes()
		if info_class == FileInfoClass.FileStandardInformation:
			return standard.to_bytes()
		if info_class == FileInfoClass.FileInternalInformation:
			return internal.to_bytes()
		if info_class == FileInfoClass.FileEaInformation:
			return ea.to_bytes()
		if info_class == FileInfoClass.FileNetworkOpenInformation:
			return network.to_bytes()
		if info_class == FileInfoClass.FileAccessInformation:
			value = FileAccessInformation()
			value.AccessFlags = handle.desired_access
			return value.to_bytes()
		if info_class == FileInfoClass.FilePositionInformation:
			return FilePositionInformation().to_bytes()
		if info_class == FileInfoClass.FileModeInformation:
			value = FileModeInformation()
			value.Mode = handle.create_options
			return value.to_bytes()
		if info_class == FileInfoClass.FileAlignmentInformation:
			return FileAlignmentInformation().to_bytes()
		if info_class in (
			FileInfoClass.FileNameInformation,
			FileInfoClass.FileNormalizedNameInformation,
		):
			value = FileNameInformation()
			value.FileName = '\\' + str(handle.relative_path).replace('/', '\\')
			return value.to_bytes()
		if info_class == FileInfoClass.FileAttributeTagInformation:
			return attributes.value.to_bytes(4, 'little') + b'\x00' * 4
		if info_class == FileInfoClass.FileAllInformation:
			value = FileAllInformation()
			value.BasicInformation = basic
			value.StandardInformation = standard
			value.InternalInformation = internal
			value.EaInformation = ea
			value.AccessInformation.AccessFlags = handle.desired_access
			value.ModeInformation.Mode = handle.create_options
			value.NameInformation.FileName = (
				'\\' + str(handle.relative_path).replace('/', '\\')
			)
			return value.to_bytes()
		raise ValueError('Unsupported file information class %s' % info_class)

	async def _filesystem_info_bytes(self, tree, info_class):
		statvfs = await self.filesystem._run_sync(
			tree.share.root.stat,
		)
		volume_serial = int(getattr(statvfs, 'st_dev', 0)) & 0xFFFFFFFF
		if info_class == FileSystemInfoClass.FileFsVolumeInformation:
			from aiosmb.wintypes.fscc.structures.FileFsVolumeInformation import (
				FileFsVolumeInformation,
			)
			value = FileFsVolumeInformation()
			value.VolumeCreationTime = convert_to_ft(statvfs.st_ctime)
			value.VolumeSerialNumber = volume_serial
			value.VolumeLabel = tree.share.name
			return value.to_bytes()

		fs_stats = await self.filesystem._run_sync(
			__import__('os').statvfs,
			str(tree.share.root),
		)
		bytes_per_sector = 512
		sectors_per_unit = max(1, int(fs_stats.f_frsize // bytes_per_sector))
		total_units = int(fs_stats.f_blocks)
		available_units = int(fs_stats.f_bavail)
		if info_class == FileSystemInfoClass.FileFsSizeInformation:
			return (
				total_units.to_bytes(8, 'little', signed=True)
				+ available_units.to_bytes(8, 'little', signed=True)
				+ sectors_per_unit.to_bytes(4, 'little')
				+ bytes_per_sector.to_bytes(4, 'little')
			)
		if info_class == FileSystemInfoClass.FileFsFullSizeInformation:
			return (
				total_units.to_bytes(8, 'little', signed=True)
				+ available_units.to_bytes(8, 'little', signed=True)
				+ available_units.to_bytes(8, 'little', signed=True)
				+ sectors_per_unit.to_bytes(4, 'little')
				+ bytes_per_sector.to_bytes(4, 'little')
			)
		if info_class == FileSystemInfoClass.FileFsDeviceInformation:
			return (7).to_bytes(4, 'little') + (0x10).to_bytes(4, 'little')
		if info_class == FileSystemInfoClass.FileFsAttributeInformation:
			fs_name = 'PYFS'.encode('utf-16-le')
			return (
				(0x00000006).to_bytes(4, 'little')
				+ (255).to_bytes(4, 'little', signed=True)
				+ len(fs_name).to_bytes(4, 'little')
				+ fs_name
			)
		raise ValueError('Unsupported filesystem information class %s' % info_class)

	async def set_info(self, msg:SMB2Message):
		try:
			command = typing.cast(SET_INFO_REQ, msg.command)
			tree, handle = self._lookup_handle(msg.header.TreeId, command.FileId)
			if tree.is_pipe or command.InfoType != QueryInfoType.FILE:
				await self.send_error(msg, NTStatus.NOT_SUPPORTED)
				return
			data = command.Data
			if command.FileInfoClass == FileInfoClass.FileEndOfFileInformation:
				await self.log(
					logging.INFO,
					'truncate file share=%s path=%r size=%s'
					% (
						self._share_name(tree),
						self._handle_name(handle),
						data.EndOfFile,
					),
				)
				if not self._access_categories(handle.desired_access)[1]:
					raise PermissionError('handle does not grant write access')
				await self.filesystem.truncate(handle, int(data.EndOfFile))
			elif command.FileInfoClass == FileInfoClass.FileDispositionInformation:
				await self.log(
					logging.INFO,
					'%s file share=%s path=%r'
					% (
						'delete' if data.DeletePending else 'keep',
						self._share_name(tree),
						self._handle_name(handle),
					),
				)
				if not self._access_categories(handle.desired_access)[2]:
					raise PermissionError('handle does not grant delete access')
				handle.delete_on_close = bool(data.DeletePending)
			elif command.FileInfoClass == FileInfoClass.FileRenameInformation:
				await self.log(
					logging.INFO,
					'rename file share=%s path=%r destination=%r'
					% (
						self._share_name(tree),
						self._handle_name(handle),
						data.FileName,
					),
				)
				if not self._access_categories(handle.desired_access)[2]:
					raise PermissionError('handle does not grant delete access')
				new_name = data.FileName
				await self.filesystem.rename(
					tree.share,
					handle.relative_path,
					new_name,
					replace_existing=bool(data.ReplaceIfExists),
				)
			elif command.FileInfoClass == FileInfoClass.FileBasicInformation:
				# Attribute/timestamp mutation is intentionally bounded for the
				# local MVP; zero fields mean "do not change".
				await self.log(
					logging.DEBUG,
					'update metadata share=%s path=%r'
					% (self._share_name(tree), self._handle_name(handle)),
				)
				pass
			else:
				await self.send_error(msg, NTStatus.INVALID_INFO_CLASS)
				return
			await self.sendSMB2(
				msg,
				SMB2Command.SET_INFO,
				SET_INFO_REPLY(),
				NTStatus.SUCCESS,
			)
		except Exception as e:
			await self.send_error(msg, status_from_exception(e))
	
	async def query_directory(self, msg:SMB2Message):
		try:
			command = typing.cast(QUERY_DIRECTORY_REQ, msg.command)
			te, directory_handle = self._lookup_handle(
				msg.header.TreeId,
				command.FileId,
			)
			if te.is_pipe or directory_handle.object_type is not FilesystemObjectType.DIRECTORY:
				raise NotADirectoryError(str(getattr(directory_handle, 'path', '')))
			pattern = command.FileName if command.FileName else '*'
			if pattern in ['\\\x00', '\\', '.', '.\x00']:
				pattern = '*'
			pattern = pattern.lstrip('\\') or '*'
			state = directory_handle.enumeration_state
			if (
				command.Flags & QueryDirectoryFlag.SMB2_RESTART_SCANS
				or command.Flags & QueryDirectoryFlag.SMB2_REOPEN
				or state.information_class is None
			):
				await self.log(
					logging.INFO,
					'list directory share=%s path=%r pattern=%r'
					% (
						self._share_name(te),
						self._handle_name(directory_handle),
						pattern,
					),
				)
				from aiosmb.commons.utils.glob2re import glob2re
				import re
				all_entries = await self.filesystem.list(
					te.share,
					directory_handle.relative_path,
				)
				directory_stat = await self.filesystem.stat_handle(
					directory_handle
				)
				all_entries = [
					DirectoryEntry(
						name='.',
						relative_path=directory_handle.relative_path,
						stat=directory_stat,
						object_type=FilesystemObjectType.DIRECTORY,
					),
					DirectoryEntry(
						name='..',
						relative_path=directory_handle.relative_path,
						stat=directory_stat,
						object_type=FilesystemObjectType.DIRECTORY,
					),
				] + all_entries
				matcher = re.compile(glob2re(pattern), re.IGNORECASE)
				filtered = [
					entry for entry in all_entries if matcher.match(entry.name)
				]
				state.reset(filtered, pattern, command.FileInformationClass)
			from aiosmb.wintypes.fscc.structures._directory import (
				FileBothDirectoryInformation,
				FileDirectoryInformation,
				FileFullDirectoryInformation,
				FileIdBothDirectoryInformation,
				FileIdFullDirectoryInformation,
				serialize_directory_information,
			)
			entry_types = {
				FileInfoClass.FileDirectoryInformation: FileDirectoryInformation,
				FileInfoClass.FileFullDirectoryInformation: FileFullDirectoryInformation,
				FileInfoClass.FileBothDirectoryInformation: FileBothDirectoryInformation,
				FileInfoClass.FileIdFullDirectoryInformation: FileIdFullDirectoryInformation,
				FileInfoClass.FileIdBothDirectoryInformation: FileIdBothDirectoryInformation,
			}
			entry_type = entry_types.get(command.FileInformationClass)
			if entry_type is None:
				await self.send_error(msg, NTStatus.INVALID_INFO_CLASS)
				return
			max_len = command.OutputBufferLength or 65535
			records = []
			for directory_entry in state.entries[state.index:]:
				st = directory_entry.stat
				is_directory = (
					directory_entry.object_type is FilesystemObjectType.DIRECTORY
				)
				record = entry_type()
				record.FileIndex = 0
				record.CreationTime = convert_to_ft(st.st_ctime)
				record.LastAccessTime = convert_to_ft(st.st_atime)
				record.LastWriteTime = convert_to_ft(st.st_mtime)
				record.ChangeTime = convert_to_ft(st.st_mtime)
				record.EndOfFile = 0 if is_directory else st.st_size
				record.AllocationSize = (
					0 if is_directory else int(
						getattr(st, 'st_blocks', 0) * 512
					)
				)
				record.FileAttributes = (
					FileAttributes.FILE_ATTRIBUTE_DIRECTORY
					if is_directory
					else FileAttributes.FILE_ATTRIBUTE_NORMAL
				)
				record.FileName = directory_entry.name
				if hasattr(record, 'FileId'):
					record.FileId = int(getattr(st, 'st_ino', 0))
				candidate = records + [record]
				if len(serialize_directory_information(candidate)) > max_len:
					break
				records.append(record)
				if command.Flags & QueryDirectoryFlag.SMB2_RETURN_SINGLE_ENTRY:
					break
			buffer = serialize_directory_information(records) if records else b''
			emitted = len(records)
			state.index += emitted

			reply = SMB2Message()
			reply.header = SMB2Header_SYNC()
			reply.header.Command = SMB2Command.QUERY_DIRECTORY
			reply.header.Flags = SMB2HeaderFlag.SMB2_FLAGS_SERVER_TO_REDIR
			reply.header.SessionId = self.SessionId
			reply.header.TreeId = msg.header.TreeId
			reply.header.CreditCharge = 1
			reply.header.CreditReq = msg.header.CreditReq if msg.header.CreditReq else 1
			
			# Check if we have no data to return (either no buffer or all entries consumed)
			if len(buffer) == 0 or (emitted == 0 and state.index >= len(state.entries)):
				# No entries matched, nothing fits, or enumeration is complete
				reply.header.Status = NTStatus.NO_MORE_FILES
				reply.command = ERROR_REPLY()
				await self.sendSMB2(msg, SMB2Command.QUERY_DIRECTORY, reply.command, NTStatus.NO_MORE_FILES)
			else:
				reply.header.Status = NTStatus.SUCCESS
				reply.command = QUERY_DIRECTORY_REPLY()
				reply.command.Data = buffer
				await self.sendSMB2(msg, SMB2Command.QUERY_DIRECTORY, reply.command, NTStatus.SUCCESS)
			#await self.sendSMB(reply)
			
		except Exception as e:
			await self.log(
				logging.ERROR,
				'list directory failed tree_id=%s: %s'
				% (msg.header.TreeId, e),
			)
			await self.send_error(msg, status_from_exception(e))

	async def close(self, msg:SMB2Message):
		try:
			command = typing.cast(CLOSE_REQ, msg.command)
			tree, handle = self._lookup_handle(msg.header.TreeId, command.FileId)
			await self.log(
				logging.DEBUG,
				'close share=%s path=%r'
				% (self._share_name(tree), self._handle_name(handle)),
			)
			reply = CLOSE_REPLY()
			reply.Flags = CloseFlag.NONE
			if isinstance(handle, FileEntry):
				if command.Flags & CloseFlag.SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB:
					st = handle.path.stat()
					reply.CreationTime = convert_to_ft(st.st_ctime)
					reply.LastAccessTime = convert_to_ft(st.st_atime)
					reply.LastWriteTime = convert_to_ft(st.st_mtime)
					reply.ChangeTime = convert_to_ft(st.st_mtime)
					reply.AllocationSize = int(
						getattr(st, 'st_blocks', 0) * 512
					)
					reply.EndofFile = st.st_size
					reply.FileAttributes = FileAttributes.FILE_ATTRIBUTE_NORMAL.value
					reply.Flags = CloseFlag.SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB
				if handle.handle is not None:
					handle.handle.close()
				tree.file_entries.pop(command.FileId, None)
				await self.sendSMB2(
					msg, SMB2Command.CLOSE, reply, NTStatus.SUCCESS
				)
				return
			if tree.is_pipe:
				await self._close_pipe(handle)
			else:
				if command.Flags & CloseFlag.SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB:
					st = await self.filesystem.stat_handle(handle)
					is_directory = (
						handle.object_type is FilesystemObjectType.DIRECTORY
					)
					reply.CreationTime = convert_to_ft(int(st.st_ctime))
					reply.LastAccessTime = convert_to_ft(int(st.st_atime))
					reply.LastWriteTime = convert_to_ft(int(st.st_mtime))
					reply.ChangeTime = convert_to_ft(int(st.st_mtime))
					reply.AllocationSize = (
						0 if is_directory else int(
							getattr(st, 'st_blocks', 0) * 512
						)
					)
					reply.EndofFile = 0 if is_directory else st.st_size
					reply.FileAttributes = (
						FileAttributes.FILE_ATTRIBUTE_DIRECTORY.value
						if is_directory
						else FileAttributes.FILE_ATTRIBUTE_NORMAL.value
					)
					reply.Flags = CloseFlag.SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB
				await self.filesystem.close(handle)
			tree.file_entries.pop(command.FileId, None)
			await self.sendSMB2(msg, SMB2Command.CLOSE, reply, NTStatus.SUCCESS)
		except Exception as e:
			await self.send_error(msg, status_from_exception(e))

	async def tree_disconnect(self, msg:SMB2Message):
		try:
			tree = self.__treeid_to_entry.get(msg.header.TreeId)
			if tree is None:
				await self.send_error(msg, NTStatus.NETWORK_NAME_DELETED)
				return
			await self.log(
				logging.INFO,
				'disconnect share=%s' % self._share_name(tree),
			)
			for handle in list(tree.file_entries.values()):
				if tree.is_pipe:
					await self._close_pipe(handle)
				else:
					try:
						await self.filesystem.close(handle)
					except InvalidHandleError:
						pass
			tree.file_entries.clear()
			self.__treeid_to_entry.pop(msg.header.TreeId, None)
			await self.sendSMB2(
				msg,
				SMB2Command.TREE_DISCONNECT,
				TREE_DISCONNECT_REPLY(),
				NTStatus.SUCCESS,
			)
		except Exception as e:
			await self.send_error(msg, status_from_exception(e))

	async def logoff(self, msg:SMB2Message):
		try:
			await self.log(logging.INFO, 'session logoff')
			for tree in list(self.__treeid_to_entry.values()):
				for handle in list(tree.file_entries.values()):
					if tree.is_pipe:
						await self._close_pipe(handle)
			await self.filesystem.close_all()
			self.__treeid_to_entry.clear()
			await self.sendSMB2(
				msg,
				SMB2Command.LOGOFF,
				LOGOFF_REPLY(),
				NTStatus.SUCCESS,
			)
			self.status = SMBConnectionStatus.SESSIONSETUP
		except Exception as e:
			await self.send_error(msg, status_from_exception(e))
	
	
	async def echo(self, msg:SMB2Message):
		try:
			command = typing.cast(ECHO_REQ, msg.command)
			reply = SMB2Message()
			reply.header = SMB2Header_SYNC()
			reply.header.Command = SMB2Command.ECHO
			reply.header.Flags = SMB2HeaderFlag.SMB2_FLAGS_SERVER_TO_REDIR
			reply.header.SessionId = self.SessionId
			reply.header.CreditCharge = msg.header.CreditCharge if msg.header.CreditCharge else 1
			reply.header.CreditReq = msg.header.CreditReq if msg.header.CreditReq else 1
			reply.header.Status = NTStatus.SUCCESS
			reply.command = ECHO_REPLY()
			await self.sendSMB2(msg, SMB2Command.ECHO, reply.command, NTStatus.SUCCESS)
		except Exception as e:
			await self.log(logging.ERROR, 'echo failed: %s' % e)
	
	async def sendSMB2(
		self,
		orgiginator:SMB2Message,
		command:SMB2Command,
		reply,
		status = NTStatus.SUCCESS,
		tree_id = None,
	):
		replymsg = SMB2Message()
		replymsg.header = SMB2Header_SYNC()
		replymsg.header.MessageId = orgiginator.header.MessageId
		replymsg.header.Command = command
		replymsg.header.Flags = SMB2HeaderFlag.SMB2_FLAGS_SERVER_TO_REDIR
		replymsg.header.SessionId = self.SessionId
		replymsg.header.TreeId = orgiginator.header.TreeId if tree_id is None else tree_id
		# Fix: CreditCharge should match the request's CreditCharge (credits consumed)
		replymsg.header.CreditCharge = orgiginator.header.CreditCharge
		# Fix: CreditReq should be the credits we're granting back to the client
		replymsg.header.CreditReq = orgiginator.header.CreditReq if orgiginator.header.CreditReq else 1
		replymsg.header.Status = status
		if self.SessionKey and (
			self.signing_required
			or orgiginator.header.Flags & SMB2HeaderFlag.SMB2_FLAGS_SIGNED
		):
			replymsg.header.Flags |= SMB2HeaderFlag.SMB2_FLAGS_SIGNED
		replymsg.command = reply
		await self.log(TRACE_LEVEL, 'send packet %s' % replymsg)
		await self.sendSMB(replymsg)