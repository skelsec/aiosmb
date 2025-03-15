from asysocks.unicomm.common.target import UniTarget, UniProto
from asysocks.unicomm.server import UniServer
from aiosmb.transport.netbios import NetBIOSPacketizer
from aiosmb.protocol.smb2.commands.negotiate import NEGOTIATE_REQ, NEGOTIATE_REPLY,NegotiateSecurityMode, NegotiateCapabilities, NegotiateDialects
from aiosmb.wintypes.dtyp.constrcuted_security.guid import *
from aiosmb.relay.serverconnection import SMBRelayServerConnection
from asyauth.protocols.spnego.relay.native import spnegorelay_ntlm_factory
from asyauth.protocols.ntlm.relay.native import NTLMRelaySettings, ntlmrelay_factory
import traceback
import asyncio

async def log_callback(msg):
	print(msg)

class SMBServerSettings:
	def __init__(self, gssapi_factory, log_callback = log_callback):
		self.gssapi_factory = gssapi_factory
		self.preferred_dialects = [NegotiateDialects.SMB202]
		self.MaxTransactSize = 0x100000
		self.MaxReadSize = 0x100000
		self.MaxWriteSize = 0x100000
		self.ServerGuid = GUID.random()
		self.RequireSigning = False
		self.log_callback = log_callback

		self.shares = {} #share_name -> path on disk
	
	@property
	def gssapi(self):
		return self.gssapi_factory()
	

class SMBRelayServer:
	def __init__(self, target, settings):
		self.target = target
		self.settings = settings
		self.server = None
		self.serving_task = None
		self.connections = {}
	
	async def print(self, msg):
		if self.settings.log_callback is not None:
			await self.settings.log_callback(msg)

	async def __handle_connection(self):
		try:
			async for connection in self.server.serve():
				await self.print('[SMBRELAY][INF] Got new connection!')
				
				try:
					smbconnection = SMBRelayServerConnection(self.settings, connection)
					if self.settings.ServerGuid not in self.connections:
						self.connections[self.settings.ServerGuid] = []
					self.connections[self.settings.ServerGuid].append(smbconnection)
					await smbconnection.run()
				except Exception as e:
					await self.print('[SMBRELAY][ERR] %s' % e)

		except Exception as e:
			traceback.print_exc()
			return
		finally:
			for connection in self.connections[self.settings.ServerGuid]:
				await connection.stop()

	async def run(self):
		self.server = UniServer(self.target, NetBIOSPacketizer())
		self.serving_task = asyncio.create_task(self.__handle_connection())
		return self.serving_task

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

		settings = SMBServerSettings(lambda: spnegorelay_ntlm_factory(auth_relay_queue, lambda: ntlmrelay_factory()))
		settings.preferred_dialects = [NegotiateDialects.SMB202]
		settings.MaxTransactSize = 0x100000
		settings.MaxReadSize = 0x100000
		settings.MaxWriteSize = 0x100000
		settings.ServerGuid = GUID.random()
		settings.RequireSigning = False
		settings.shares = {} #share_name -> path on disk

		server = SMBRelayServer(target, settings)
		server_task = await server.run()
		await server_task
	except Exception as e:
		traceback.print_exc()
		return
if __name__ == '__main__':
	asyncio.run(amain())
