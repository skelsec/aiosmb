from asysocks.unicomm.common.target import UniTarget, UniProto
from asysocks.unicomm.server import UniServer
from aiosmb.transport.netbios import NetBIOSPacketizer
from aiosmb.protocol.smb2.commands.negotiate import NEGOTIATE_REQ, NEGOTIATE_REPLY,NegotiateSecurityMode, NegotiateCapabilities, NegotiateDialects
from aiosmb.wintypes.dtyp.constrcuted_security.guid import *
from aiosmb.server.serverconnection import SMBServerConnection
from asyauth.protocols.spnego.server.native import spnegoserver_ntlm_factory
from asyauth.protocols.ntlm.server.native import ntlmserver_factory
from asyauth.common.credentials.ntlm import NTLMCredential
from aiosmb.server.authentication import (
	anonymous_authenticator_factory,
	ntlm_authenticator_factory,
	ntlm_hash_authenticator_factory,
)
import traceback
import asyncio
import logging

from aiosmb import logger


TRACE_LEVEL = 5
logging.addLevelName(TRACE_LEVEL, 'TRACE')

async def log_callback(msg, level=logging.INFO):
	logger.log(level, msg)

class SMBServerSettings:
	def __init__(
		self,
		gssapi_factory,
		log_callback=log_callback,
		log_level=logging.INFO,
		disable_ess=False,
	):
		self.gssapi_factory = gssapi_factory
		self.preferred_dialects = [NegotiateDialects.SMB202]
		self.MaxTransactSize = 0x100000
		self.MaxReadSize = 0x100000
		self.MaxWriteSize = 0x100000
		self.MaxCredits = 128
		self.ServerGuid = GUID.random()
		self.ServerName = 'AIOSMB'
		self.ServerComment = 'aiosmb SMB server'
		self.RequireSigning = False
		self.DisableESS = disable_ess
		self.log_callback = log_callback
		self.log_level = log_level

		self.shares = {} #share_name -> path on disk
		self.filesystem_backend_factory = None

	async def emit_log(self, level, message):
		if self.log_callback is None or level < self.log_level:
			return
		if self.log_callback is log_callback:
			await self.log_callback(message, level)
			return
		await self.log_callback(message)

	@classmethod
	def from_password(
		cls,
		username,
		password,
		domain='',
		log_callback=log_callback,
		disable_ess=False,
	):
		return cls(
			ntlm_authenticator_factory(password, username, domain),
			log_callback=log_callback,
			disable_ess=disable_ess,
		)

	@classmethod
	def from_nt_hash(
		cls,
		username,
		nt_hash,
		domain='',
		log_callback=log_callback,
		disable_ess=False,
	):
		return cls(
			ntlm_hash_authenticator_factory(nt_hash, username, domain),
			log_callback=log_callback,
			disable_ess=disable_ess,
		)

	@classmethod
	def from_anonymous(
		cls,
		log_callback=log_callback,
		disable_ess=False,
	):
		return cls(
			anonymous_authenticator_factory(),
			log_callback=log_callback,
			disable_ess=disable_ess,
		)

	@classmethod
	def anonymous(cls, log_callback=log_callback, disable_ess=False):
		return cls.from_anonymous(
			log_callback=log_callback,
			disable_ess=disable_ess,
		)

	def create_new_gssapi(self, connection):
		gssapi = self.gssapi_factory()
		if self.DisableESS:
			credential = getattr(gssapi, 'credential', None)
			if credential is None:
				raise ValueError(
					'DisableESS requires an NTLM credential-backed authenticator'
				)
			credential.disable_ess = True
		gssapi.set_connection_info(connection)
		return gssapi

	def create_filesystem_backend(self):
		if self.filesystem_backend_factory is not None:
			return self.filesystem_backend_factory(self)
		from aiosmb.server.filesystem import LocalFilesystemBackend
		return LocalFilesystemBackend(self.shares)
	

class SMBServer:
	def __init__(self, target, settings):
		self.target = target
		self.settings = settings
		self.server = None
		self.serving_task = None
		self.connections = {}
		self.connection_ctr = 0
	
	async def log(self, level, msg):
		level_name = logging.getLevelName(level)
		await self.settings.emit_log(
			level,
			'[SMBSERVER][%s] %s' % (level_name, msg),
		)

	async def __handle_connection(self, connection):
		smbconnection = None
		connection_id = None
		try:
			self.connection_ctr += 1
			connection_id = self.connection_ctr
			await self.log(
				logging.INFO,
				'connection %s accepted' % connection_id,
			)
			
			try:
				smbconnection = SMBServerConnection(self.settings, connection, connection_id=connection_id)
				self.connections.setdefault(self.settings.ServerGuid, []).append(smbconnection)
				connection_task = await smbconnection.run()
				await connection_task
				await self.log(
					logging.INFO,
					'connection %s closed' % connection_id,
				)
			except Exception as e:
				await self.log(
					logging.ERROR,
					'connection %s failed: %s' % (connection_id, e),
				)

		except Exception as e:
			await self.log(
				logging.ERROR,
				'connection %s stopped unexpectedly: %s'
				% (connection_id, e),
			)
			return
		finally:
			if smbconnection is not None:
				await smbconnection.stop()
				connections = self.connections.get(self.settings.ServerGuid, [])
				if smbconnection in connections:
					connections.remove(smbconnection)
				if not connections:
					self.connections.pop(self.settings.ServerGuid, None)

	async def run(self):
		self.server = UniServer(self.target, NetBIOSPacketizer())
		return await self.server.serve_callback(self.__handle_connection)

async def test_relay_queue(rq):
	try:
		from aiosmb.connection import SMBConnection
		from aiosmb.commons.connection.target import SMBTarget
		from aiosmb.commons.interfaces.machine import SMBMachine
		test_target = SMBTarget('10.10.10.2')
		while True:
			item = await rq.get()
			print(item)
			connection = SMBConnection(item, test_target, preserve_gssapi=False, nosign=True)
			_, err = await connection.login()
			if err is not None:
				print('SMB client login err: %s' % err)
				print(traceback.format_tb(err.__traceback__))
				continue
			machine = SMBMachine(connection)
			async for share, err in machine.list_shares():
				if err is not None:
					print('SMB client list_shares err: %s' % err)
					continue
				print(share)

	except Exception as e:
		traceback.print_exc()
		return

async def amain():
	try:
		auth_relay_queue = asyncio.Queue()
		x = asyncio.create_task(test_relay_queue(auth_relay_queue))
		target = UniTarget('0.0.0.0', 445, UniProto.SERVER_TCP)

		settings = SMBServerSettings(lambda: spnegoserver_ntlm_factory(auth_relay_queue, lambda: ntlmserver_factory()))
		settings.preferred_dialects = [NegotiateDialects.SMB202]
		settings.MaxTransactSize = 0x100000
		settings.MaxReadSize = 0x100000
		settings.MaxWriteSize = 0x100000
		settings.ServerGuid = GUID.random()
		settings.RequireSigning = False
		settings.shares = {
			'test': '/tmp/smbshare',
		} #share_name -> path on disk

		server = SMBServer(target, settings)
		server_task, err = await server.run()
		if err is not None:
			print('SMB server error: %s' % err)
			return
		await server_task
	except Exception as e:
		traceback.print_exc()
		return
if __name__ == '__main__':
	asyncio.run(amain())
