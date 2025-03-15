

#
# Currently supported auth types:
#      NTLM auth using SMBNTLM implementation
#      Kerberos auth using SMBSPNEGO implementation (GSSAPI)
#
# Not supported currently:
#      NTLM via SPNEGO (GSSAPI)
#      Direct kerberos auth (not sure if this is even in the protocol)
#      NETLOGON
#
# TODO: netlogon implementation (needs to be implemented in connection.py as well!)
# TODO: GSS over NTLM (but I'm not sure if the protocol allows that)
from typing import List
import copy
from asyauth.common.credentials.spnego import SPNEGOCredential
from asyauth.common.credentials import UniCredential
from asyauth.common.constants import asyauthSecret

class DCERPCAuth:
	def __init__(self):
		self.ntlm = None
		self.kerberos = None
		self.gssapi = None
		self.netlogon = None

	@staticmethod
	def from_smb_gssapi(gssapi):
		auth = DCERPCAuth()
		auth.gssapi = gssapi.get_copy()
		if 'MS KRB5 - Microsoft Kerberos 5' in gssapi.list_original_conexts():
			auth.kerberos = gssapi.get_original_context('MS KRB5 - Microsoft Kerberos 5')
		if 'NTLMSSP - Microsoft NTLM Security Support Provider' in gssapi.list_original_conexts():
			auth.ntlm = gssapi.get_original_context('NTLMSSP - Microsoft NTLM Security Support Provider')

		return auth
	
	@staticmethod
	def from_components(username:str, secret:str, secrettype:str = 'password', 
							domain:str = None, dcip:str = None, proxies = None, authproto:str = 'ntlm',
							altname:str = None, altdomain:str = None, etype:List[int]=[23,17,18], certdata:str= None, keydata:str=None):
		"""Builds a new SMBConnectionFactory object from scratch.
		This doesn't support all features of the SMBTarget and SMBCredential objects, but it's a quick way to build a connection factory."""
		import ipaddress
		if username.count('\\') == 1:
			domain, username = username.split('\\')
		if domain is not None:
			domain = domain.upper()

		if authproto is None:
			# making it default
			authproto = 'NTLM'

		authproto = authproto.upper()
		secrettype = asyauthSecret(secrettype.upper())
		if authproto == 'NTLM':
			from asyauth.common.credentials.ntlm import NTLMCredential
			credential = NTLMCredential(
				secret,
				username, 
				domain, 
				secrettype, 
			)
		elif authproto == 'KERBEROS':
			from asyauth.common.credentials.kerberos import KerberosCredential
			credential = KerberosCredential(
				secret,
				username,
				domain,
				secrettype, 
				target = target,
				altname=altname,
				altdomain=altdomain,
				etype=[23,17,18],
				certdata=certdata,
				keydata=keydata,
			)
		
		else:
			raise Exception('Unknown authproto: %s' % authproto)
		
		gssapi = SPNEGOCredential([copy.deepcopy(credential)]).build_context()

		return DCERPCAuth.from_smb_gssapi(gssapi)

