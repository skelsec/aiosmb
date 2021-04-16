import enum
import platform
import os

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
				if creds.username is None and creds.domain is None:
					ntlmcred.is_guest = True
				else:
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
			
			if creds.secret_type == SMBCredentialsSecretType.KEYTAB:
				filename = creds.secret
				if creds.secret.upper() == 'ENV':
					filename = os.environ['KRB5KEYTAB']

				kc = KerberosCredential.from_keytab(filename, creds.username, creds.domain)

			elif creds.secret_type == SMBCredentialsSecretType.CCACHE:
				filename = creds.secret
				if creds.secret.upper() == 'ENV':
					try:
						filename = os.environ['KRB5CCACHE']
					except:
						raise Exception('Kerberos auth missing environment variable KRB5CCACHE')
				kc = KerberosCredential.from_ccache_file(filename)
				kc.username = creds.username
				kc.domain = creds.domain
			
			elif creds.secret_type == SMBCredentialsSecretType.KIRBI:
				filename = creds.secret
				kc = KerberosCredential.from_kirbi(filename)
				kc.username = creds.username
				kc.domain = creds.domain
			
			else:
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

			if kc is None:
				raise Exception('No suitable secret type found to set up kerberos!')
			
				
			kcred = SMBKerberosCredential()
			kcred.ccred = kc
			kcred.spn = KerberosSPN.from_target_string(target.to_target_string())
			
			if target.proxy is not None:
				if target.proxy.type in [SMBProxyType.WSNET, SMBProxyType.SOCKS5, SMBProxyType.SOCKS5_SSL, SMBProxyType.SOCKS4, SMBProxyType.SOCKS4_SSL]:
					kcred.target = KerberosTarget(target.dc_ip)
					kcred.target.proxy = KerberosProxy()
					kcred.target.proxy.target = copy.deepcopy(target.proxy.target)
					kcred.target.proxy.target[-1].endpoint_ip = target.dc_ip
					kcred.target.proxy.target[-1].endpoint_port = 88
				
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

		elif creds.authentication_type.value.startswith('MPN'):
			if creds.authentication_type in [SMBAuthProtocol.MPN_SSL_NTLM, SMBAuthProtocol.MPN_NTLM]:
				from aiosmb.authentication.ntlm.mpn import SMBNTLMMPN
				ntlmcred = SMBMPNCredential()
				ntlmcred.type = 'NTLM'
				ntlmcred.is_ssl = True if creds.authentication_type == SMBAuthProtocol.MPN_SSL_NTLM else False
				ntlmcred.parse_settings(creds.settings)
				
				handler = SMBNTLMMPN(ntlmcred)
				#setting up SPNEGO
				spneg = SPNEGO()
				spneg.add_auth_context('NTLMSSP - Microsoft NTLM Security Support Provider', handler)
				return spneg

			elif creds.authentication_type in [SMBAuthProtocol.MPN_SSL_KERBEROS, SMBAuthProtocol.MPN_KERBEROS]:
				from aiosmb.authentication.kerberos.mpn import SMBKerberosMPN

				ntlmcred = SMBMPNCredential()
				ntlmcred.type = 'KERBEROS'
				ntlmcred.target = creds.target
				if creds.username is not None:
					ntlmcred.username = '<CURRENT>'
				if creds.domain is not None:
					ntlmcred.domain = '<CURRENT>'
				if creds.secret is not None:
					ntlmcred.password = '<CURRENT>'
				ntlmcred.is_guest = False
				ntlmcred.is_ssl = True if creds.authentication_type == SMBAuthProtocol.MPN_SSL_KERBEROS else False
				ntlmcred.parse_settings(creds.settings)

				handler = SMBKerberosMPN(ntlmcred)
				#setting up SPNEGO
				spneg = SPNEGO()
				spneg.add_auth_context('MS KRB5 - Microsoft Kerberos 5', handler)
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

		elif creds.authentication_type.value.startswith('WSNET'):
			if creds.authentication_type in [SMBAuthProtocol.WSNET_NTLM]:
				from aiosmb.authentication.ntlm.wsnet import SMBWSNetNTLMAuth
				
				ntlmcred = SMBWSNETCredential()
				ntlmcred.type = 'NTLM'
				if creds.username is not None:
					ntlmcred.username = '<CURRENT>'
				if creds.domain is not None:
					ntlmcred.domain = '<CURRENT>'
				if creds.secret is not None:
					ntlmcred.password = '<CURRENT>'
				ntlmcred.is_guest = False
				
				handler = SMBWSNetNTLMAuth(ntlmcred)
				spneg = SPNEGO()
				spneg.add_auth_context('NTLMSSP - Microsoft NTLM Security Support Provider', handler)
				return spneg
			

			elif creds.authentication_type in [SMBAuthProtocol.WSNET_KERBEROS]:
				from aiosmb.authentication.kerberos.wsnet import SMBWSNetKerberosAuth

				ntlmcred = SMBWSNETCredential()
				ntlmcred.type = 'KERBEROS'
				ntlmcred.target = creds.target
				if creds.username is not None:
					ntlmcred.username = '<CURRENT>'
				if creds.domain is not None:
					ntlmcred.domain = '<CURRENT>'
				if creds.secret is not None:
					ntlmcred.password = '<CURRENT>'
				ntlmcred.is_guest = False

				handler = SMBWSNetKerberosAuth(ntlmcred)
				#setting up SPNEGO
				spneg = SPNEGO()
				spneg.add_auth_context('MS KRB5 - Microsoft Kerberos 5', handler)
				return spneg
		
		elif creds.authentication_type.value.startswith('SSPIPROXY'):
			if creds.authentication_type == SMBAuthProtocol.SSPIPROXY_NTLM:
				from aiosmb.authentication.ntlm.sspiproxy import SMBSSPIProxyNTLMAuth
				
				ntlmcred = SMBSSPIProxyCredential()
				ntlmcred.type = 'NTLM'
				if creds.username is not None:
					ntlmcred.username = '<CURRENT>'
				if creds.domain is not None:
					ntlmcred.domain = '<CURRENT>'
				if creds.secret is not None:
					ntlmcred.password = '<CURRENT>'
				ntlmcred.is_guest = False
				ntlmcred.host = creds.settings['host'][0]
				ntlmcred.port = int(creds.settings['port'][0])
				ntlmcred.proto = 'ws'
				if 'proto' in creds.settings:
					ntlmcred.proto = creds.settings['proto'][0]
				if 'agentid' in creds.settings:
					ntlmcred.agent_id = bytes.fromhex(creds.settings['agentid'][0])
				
				handler = SMBSSPIProxyNTLMAuth(ntlmcred)
				spneg = SPNEGO()
				spneg.add_auth_context('NTLMSSP - Microsoft NTLM Security Support Provider', handler)
				return spneg
			

			elif creds.authentication_type == SMBAuthProtocol.SSPIPROXY_KERBEROS:
				from aiosmb.authentication.kerberos.sspiproxy import SMBSSPIProxyKerberosAuth

				ntlmcred = SMBSSPIProxyCredential()
				ntlmcred.type = 'KERBEROS'
				ntlmcred.target = creds.target
				if creds.username is not None:
					ntlmcred.username = '<CURRENT>'
				if creds.domain is not None:
					ntlmcred.domain = '<CURRENT>'
				if creds.secret is not None:
					ntlmcred.password = '<CURRENT>'
				ntlmcred.is_guest = False
				ntlmcred.host = creds.settings['host'][0]
				ntlmcred.port = int(creds.settings['port'][0])
				ntlmcred.proto = 'ws'
				if 'proto' in creds.settings:
					ntlmcred.proto = creds.settings['proto'][0]
				if 'agentid' in creds.settings:
					ntlmcred.agent_id = bytes.fromhex(creds.settings['agentid'][0])

				handler = SMBSSPIProxyKerberosAuth(ntlmcred)
				#setting up SPNEGO
				spneg = SPNEGO()
				spneg.add_auth_context('MS KRB5 - Microsoft Kerberos 5', handler)
				return spneg
		