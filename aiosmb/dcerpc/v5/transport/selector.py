from aiosmb.dcerpc.v5.common.connection.target import DCERPCTargetType
from aiosmb.dcerpc.v5.transport.smb import DCERPCSMBTransport
from aiosmb.dcerpc.v5.transport.tcp import DCERPCTCPTransport

class DCERPCTransportSelector:
	def __init__(self):
		pass

	async def select(self, target):
		if target.type == DCERPCTargetType.TCP:
			return DCERPCTCPTransport(target)
		
		elif target.type == DCERPCTargetType.SMB:
			return DCERPCSMBTransport(target)

		
		