import enum
import platform

import copy
from aiosmb.commons.connection.credential import *
from aiosmb.commons.connection.proxy import  SMBProxyType
from aiosmb.authentication.spnego.native import SPNEGO
from aiosmb.authentication.ntlm.native import NTLMAUTHHandler, NTLMHandlerSettings
from aiosmb.authentication.kerberos.native import SMBKerberos
from minikerberos.common.target import KerberosTarget
from minikerberos.common.proxy import KerberosProxy
from minikerberos.common.creds import KerberosCredential
from minikerberos.common.spn import KerberosSPN

from minikerberos.network.selector import KerberosClientSocketSelector


if platform.system().upper() == 'WINDOWS':
	from aiosmb.authentication.kerberos.sspi import SMBKerberosSSPI
	from aiosmb.authentication.ntlm.sspi import SMBNTLMSSPI

class AuthenticatorBuilder:
	def __init__(self):
		pass
	
	@staticmethod
	def to_spnego_cred(creds, target = None):
		if creds.authentication_type == SMBAuthProtocol.NTLM:
			ntlmcred = SMBNTLMCredential()
			ntlmcred.username = creds.username
			ntlmcred.domain = creds.domain if creds.domain is not None else ''
			ntlmcred.workstation = None
			ntlmcred.is_guest = False
			
			if creds.secret is None:
				raise Exception('NTLM authentication requres password!')
			if creds.secret_type == SMBCredentialsSecretType.NT:
				ntlmcred.nt_hash = creds.secret
			elif creds.secret_type == SMBCredentialsSecretType.PASSWORD:
				ntlmcred.password = creds.secret
			
			settings = NTLMHandlerSettings(ntlmcred)
			handler = NTLMAUTHHandler(settings)
			
			#setting up SPNEGO
			spneg = SPNEGO()
			spneg.add_auth_context('NTLMSSP - Microsoft NTLM Security Support Provider', handler)
			
			return spneg
		
		elif creds.authentication_type == SMBAuthProtocol.KERBEROS:
			if target is None:
				raise Exception('Target must be specified with Kerberos!')
				
			if target.hostname is None:
				raise Exception('target must have a domain name or hostname for kerberos!')
				
			if target.dc_ip is None:
				raise Exception('target must have a dc_ip for kerberos!')
			
			kc = KerberosCredential()
			kc.username = creds.username
			kc.domain = creds.domain
			if creds.secret_type == SMBCredentialsSecretType.PASSWORD:
				kc.password = creds.secret
			elif creds.secret_type == SMBCredentialsSecretType.NT:
				kc.nt_hash = creds.secret
				
			elif creds.secret_type == SMBCredentialsSecretType.AES:
				if len(creds.secret) == 32:
					kc.kerberos_key_aes_128 = creds.secret
				elif len(creds.secret) == 64:
					kc.kerberos_key_aes_256 = creds.secret
					
			elif creds.secret_type == SMBCredentialsSecretType.RC4:
				kc.kerberos_key_rc4 = creds.secret
			
			elif creds.secret_type == SMBCredentialsSecretType.RC4:
				kc.ccache = creds.secret
			else:
				raise Exception('No suitable secret type found to set up kerberos!')
			
				
			kcred = SMBKerberosCredential()
			kcred.ccred = kc
			kcred.spn = KerberosSPN.from_target_string(target.to_target_string())
			
			if target.proxy is not None:
				if target.proxy.type in [SMBProxyType.SOCKS5, SMBProxyType.SOCKS5_SSL, SMBProxyType.SOCKS4, SMBProxyType.SOCKS4_SSL]:
					kcred.target = KerberosTarget(target.dc_ip)
					kcred.target.proxy = KerberosProxy()
					kcred.target.proxy.target = copy.deepcopy(target.proxy.target)
					kcred.target.proxy.target.endpoint_ip = target.dc_ip
					kcred.target.proxy.target.endpoint_port = 88
					kcred.target.proxy.creds = copy.deepcopy(target.proxy.auth)
				
				elif target.proxy.type in [SMBProxyType.MULTIPLEXOR, SMBProxyType.MULTIPLEXOR_SSL]:
					kcred.target = KerberosTarget(target.dc_ip)
					kcred.target.proxy = copy.deepcopy(target.proxy)
			else:
				kcred.target = KerberosTarget(target.dc_ip)
			handler = SMBKerberos(kcred)
			
			#setting up SPNEGO
			spneg = SPNEGO()
			spneg.add_auth_context('MS KRB5 - Microsoft Kerberos 5', handler)
			return spneg
			
		elif creds.authentication_type == SMBAuthProtocol.SSPI_KERBEROS:
			if target is None:
				raise Exception('Target must be specified with Kerberos SSPI!')
				
			kerbcred = SMBKerberosSSPICredential()
			kerbcred.client = None #creds.username #here we could submit the domain as well for impersonation? TODO!
			kerbcred.password = creds.secret
			kerbcred.target = target.to_target_string()
			
			handler = SMBKerberosSSPI(kerbcred)
			#setting up SPNEGO
			spneg = SPNEGO()
			spneg.add_auth_context('MS KRB5 - Microsoft Kerberos 5', handler)
			return spneg
		
		elif creds.authentication_type == SMBAuthProtocol.SSPI_NTLM:
			ntlmcred = SMBNTLMSSPICredential()
			ntlmcred.client = creds.username #here we could submit the domain as well for impersonation? TODO!
			ntlmcred.password = creds.secret
			
			handler = SMBNTLMSSPI(ntlmcred)
			#setting up SPNEGO
			spneg = SPNEGO()
			spneg.add_auth_context('NTLMSSP - Microsoft NTLM Security Support Provider', handler)
			return spneg

		elif creds.authentication_type.value.startswith('MULTIPLEXOR'):
			if creds.authentication_type in [SMBAuthProtocol.MULTIPLEXOR_SSL_NTLM, SMBAuthProtocol.MULTIPLEXOR_NTLM]:
				from aiosmb.authentication.ntlm.multiplexor import SMBNTLMMultiplexor

				ntlmcred = SMBMultiplexorCredential()
				ntlmcred.type = 'NTLM'
				if creds.username is not None:
					ntlmcred.username = '<CURRENT>'
				if creds.domain is not None:
					ntlmcred.domain = '<CURRENT>'
				if creds.secret is not None:
					ntlmcred.password = '<CURRENT>'
				ntlmcred.is_guest = False
				ntlmcred.is_ssl = True if creds.authentication_type == SMBAuthProtocol.MULTIPLEXOR_SSL_NTLM else False
				ntlmcred.parse_settings(creds.settings)
				
				handler = SMBNTLMMultiplexor(ntlmcred)
				#setting up SPNEGO
				spneg = SPNEGO()
				spneg.add_auth_context('NTLMSSP - Microsoft NTLM Security Support Provider', handler)
				return spneg

			elif creds.authentication_type in [SMBAuthProtocol.MULTIPLEXOR_SSL_KERBEROS, SMBAuthProtocol.MULTIPLEXOR_KERBEROS]:
				from aiosmb.authentication.kerberos.multiplexor import SMBKerberosMultiplexor

				ntlmcred = SMBMultiplexorCredential()
				ntlmcred.type = 'KERBEROS'
				ntlmcred.target = creds.target
				if creds.username is not None:
					ntlmcred.username = '<CURRENT>'
				if creds.domain is not None:
					ntlmcred.domain = '<CURRENT>'
				if creds.secret is not None:
					ntlmcred.password = '<CURRENT>'
				ntlmcred.is_guest = False
				ntlmcred.is_ssl = True if creds.authentication_type == SMBAuthProtocol.MULTIPLEXOR_SSL_NTLM else False
				ntlmcred.parse_settings(creds.settings)

				handler = SMBKerberosMultiplexor(ntlmcred)
				#setting up SPNEGO
				spneg = SPNEGO()
				spneg.add_auth_context('MS KRB5 - Microsoft Kerberos 5', handler)
				return spneg

			
			
			
		