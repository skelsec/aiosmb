from aiosmb.dcerpc.v5.common.connection.authentication import DCERPCAuth
from aiosmb.dcerpc.v5.common.connection.target import DCERPCSMBTarget
from aiosmb.dcerpc.v5.connection import DCERPC5Connection
from aiosmb.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_WINNT

class SMBDCEFactory:
	def __init__(self, smb_connection, filename):
		self.smb_connection = smb_connection
		self.filename = filename
	
	def get_dce_rpc(self):
		dcerpc_target = DCERPCSMBTarget(
			None, 
			self.smb_connection.target.get_hostname_or_ip(), 
			pipe = self.filename, 
			smb_connection = self.smb_connection, 
			timeout = self.smb_connection.target.timeout
		)
		#print(str(dcerpc_target))
		dcerpc_auth = DCERPCAuth.from_smb_gssapi(self.smb_connection.gssapi)
		#print(str(dcerpc_auth))
		conn = DCERPC5Connection(dcerpc_auth, dcerpc_target)
		
		if dcerpc_auth.ntlm is not None:
			conn.set_auth_type(RPC_C_AUTHN_WINNT)
		if dcerpc_auth.kerberos is not None:
			conn.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)

		#auth level must be set elsewhere, this function cannot fuigure out your needs!
		
		return conn