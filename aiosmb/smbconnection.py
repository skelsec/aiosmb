import enum
import asyncio

from aiosmb.network.network import TCPSocket
from aiosmb.network.netbios_transport import NetBIOSTransport
from aiosmb.protocol.smb.command_codes import SMBCommand
from aiosmb.commons.ntstatus import NTStatus
from aiosmb.protocol.smb.header import SMBHeader, SMBHeaderFlags2Enum
from aiosmb.protocol.smb.message import SMBMessage
from aiosmb.protocol.smb.commands import *
from aiosmb.protocol.smb2.message import SMB2Message
from aiosmb.protocol.smb2.commands import *

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
		self.SequenceWindow = 0
		self.MaxTransactSize = 0
		self.MaxReadSize = 0
		self.MaxWriteSize = 0
		self.ServerGuid = None
		self.RequireSigning = False
		self.ServerName = None
		
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
		
		self.SessionID = 0
		
	async def __handle_smb_in(self):
		"""
		Waits from SMB messages from the NetBIOSTransport in_queue, and fills the connection table.
		This function started automatically when calling connect.
		"""
		while not self.shutdown_evt.is_set():
			msg = await self.netbios_transport.in_queue.get()
			
			if isinstance(msg, SMB2Transform):
				#message is encrypted
				#this point we should decrypt it and only store the decrypted part in the OutstandingResponses table
				#but for now we just thropw exception bc encryption is not implemented
				raise Exception('Encrypted SMBv2 message recieved, but encryption is not yet supported!')
			
			self.OutstandingResponses[msg.header.MessageId] = msg
			if msg.header.MessageId in self.OutstandingResponsesEvent:
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
		
		print('sleeping')
		await asyncio.sleep(10)
		
	async def session_setup(self):
	
		command = SESSION_SETUP_REQ()
		command.Buffer = self.gssapi.authenticate(None)
	
		command.Flags = 0
		command.SecurityMode = 0
		command.Capabilities = 0
		command.Channel      = 0
		command.PreviousSessionId    = 0
		
		message_id = await self.sendSMB(msg)
		
		
	async def recvSMB(self, message_id = None):
		"""
		Returns an SMB message from the outstandingresponse dict, OR waits until the expected message_id appears.
		If message_id is None if will pop the first message from the outstandingresponse OR wait for the next available message.
		"""
		if message_id not in self.OutstandingResponses:
			if message_id not in self.OutstandingResponsesEvent:
				self.OutstandingResponsesEvent[message_id] = asyncio.Event()
			
			print('waiting')
			await self.OutstandingResponsesEvent[message_id].wait()
		
		msg = self.OutstandingResponses.pop(message_id)
		
		if message_id in self.OutstandingResponsesEvent:
			del self.OutstandingResponsesEvent[message_id]
		
		return msg
		
		
	async def sendSMB(self, msg):
		"""
		Sends an SMB message to teh remote endpoint.
		
		Returns: MessageId integer
		"""
		if self.status == SMBConnectionStatus.NEGOTIATING:
			await self.netbios_transport.out_queue.put(msg)
			return 0
		
		if msg.header.Command is not SMB2Command.CANCEL:
			msg.header.MessageID = self.SequenceWindow
			self.SequenceWindow += 1
		msg.header.SessionID = self.SessionID
		
		if self.status != SMBConnectionStatus.NEGOTIATING:
			msg.header.Credit = 127
		
		message_id = msg.header.MessageID
		
		#signinggoes here
		#encryption goes here
		
		await self.netbios_transport.out_queue.put(msg)
		
			
async def test(target):
	connection = SMBConnection(None, [SMBDialect.SMB2_2])
	await connection.connect(target)
	await connection.negotiate()
			
if __name__ == '__main__':
	target = SMBTarget()
	target.ip = '10.10.10.2'
	target.port = 445

	asyncio.run(test(target))
	
	