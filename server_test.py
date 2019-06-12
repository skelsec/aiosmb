import asyncio

from aiosmb.network.tcp_server import TCPServerSocket
from aiosmb.commons.smbcredential import SMBCredential
from aiosmb.commons.authenticator_builder import AuthenticatorBuilder
from aiosmb.ntlm.auth_handler import NTLMAUTHHandler, NTLMHandlerSettings
from aiosmb.spnego.spnego import SPNEGO


class SMBServerSettings:
	def __init__(self, client_gssapi, server_gssapi = None):
		self.client_gssapi = client_gssapi
		self.server_gssapi = server_gssapi


async def test_server(tss):
	task = await tss.run()
	await task
	print('Over!')



if __name__ == '__main__':
	ip = '0.0.0.0'

	#connection_string = 'TEST/victim/ntlm/password:Passw0rd!1@win2019ad.test.corp/10.10.10.2'
	#credential = SMBCredential.from_connection_string(connection_string)
	#spneg = AuthenticatorBuilder.to_spnego_cred(credential, None)
	
	#ntlmcred = SMBNTLMCredential()
	#ntlmcred.username = 'test'
	#ntlmcred.domain = 'TEST.CORP'
	#ntlmcred.workstation = None
	#ntlmcred.is_guest = False
	#ntlmcred.password = 'aaa'
	credential = None
	
	settings = NTLMHandlerSettings(credential, mode = 'SERVER', template_name = 'Windows2003')
	handler = NTLMAUTHHandler(settings)
	
	#setting up SPNEGO
	spneg = SPNEGO('SERVER')
	spneg.add_auth_context('NTLMSSP - Microsoft NTLM Security Support Provider', handler)
	
	server_settings = SMBServerSettings(spneg)
	

	tss = TCPServerSocket(ip, server_settings)

	asyncio.run(test_server(tss))