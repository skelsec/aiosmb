

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
from asyauth.common.constants import asyauthProtocol
from asyauth.common.credentials.ntlm import NTLMCredential
from asyauth.common.credentials.kerberos import KerberosCredential

class DCERPCAuth:
	def __init__(self):
		self.ntlm = None
		self.kerberos = None
		self.gssapi = None
		self.netlogon = None
		self.domain = None
		self.__original_credential = None # used to store the original credential for deep copying when from_unicredential is called

	def get_copy(self):
		"""Create a fresh copy of this authentication object.
		
		This is needed because NTLM/Kerberos contexts have internal state
		that gets consumed during authentication. For multiple connections,
		each needs its own fresh context.
		"""
		if self.__original_credential is not None:
			return DCERPCAuth.from_unicredential(copy.deepcopy(self.__original_credential))
		if self.gssapi is not None:
			return DCERPCAuth.from_smb_gssapi(self.gssapi.get_copy())
		# Fallback: create new instance and deep copy components
		auth = DCERPCAuth()
		if self.ntlm is not None:
			auth.ntlm = copy.deepcopy(self.ntlm)
		if self.kerberos is not None:
			auth.kerberos = copy.deepcopy(self.kerberos)
		if self.netlogon is not None:
			auth.netlogon = copy.deepcopy(self.netlogon)
		return auth

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
	def from_unicredential(credential:KerberosCredential | NTLMCredential):
		auth = DCERPCAuth()
		auth.__original_credential = copy.deepcopy(credential)
		if isinstance(auth.__original_credential, NTLMCredential):
			auth.ntlm = copy.deepcopy(credential).build_context()
		elif isinstance(auth.__original_credential, KerberosCredential):
			auth.kerberos = copy.deepcopy(credential).build_context()
		else:
			raise Exception('Unknown credential type: %s' % type(credential))
		auth.gssapi = SPNEGOCredential([copy.deepcopy(auth.__original_credential)]).build_context()
		auth.domain = credential.domain

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
			
			credential = NTLMCredential(
				secret,
				username, 
				domain, 
				secrettype, 
			)
		elif authproto == 'KERBEROS':
			
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

		auth = DCERPCAuth.from_smb_gssapi(gssapi)
		auth.domain = domain
		return auth

