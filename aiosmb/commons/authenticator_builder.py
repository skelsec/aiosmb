import enum
import platform

from aiosmb.commons.smbcredential import *
from aiosmb.spnego.spnego import SPNEGO
from aiosmb.ntlm.auth_handler import NTLMAUTHHandler, NTLMHandlerSettings
from aiosmb.kerberos.kerberos import SMBKerberos
from minikerberos.common import KerberosTarget, KerberosCredential
from minikerberos.aiocommunication import KerberosSocketAIO


if platform.system().upper() == 'WINDOWS':
	from aiosmb.kerberos.kerberos_sspi import SMBKerberosSSPI
	from aiosmb.ntlm.ntlm_sspi import SMBNTLMSSPI

class AuthenticatorBuilder:
	def __init__(self):
		pass
	
	@staticmethod
	def to_spnego_cred(creds, target = None):
		if creds.authentication_type == SMBCredentialsAuthType.NTLM:
			ntlmcred = SMBNTLMCredential()
			ntlmcred.username = creds.username
			ntlmcred.domain = creds.domain if creds.domain is not None else ''
			ntlmcred.workstation = None
			ntlmcred.is_guest = False
			
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
			
		elif creds.authentication_type == SMBCredentialsAuthType.KERBEROS:
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
			kcred.ccred = kc #KerberosCredential
			kcred.ksoc = KerberosSocketAIO(target.dc_ip) #KerberosSocketAIO
			kcred.target = KerberosTarget.from_target_string(target.to_target_string()) #KerberosTarget
			
			handler = SMBKerberos(kcred)
			
			#setting up SPNEGO
			spneg = SPNEGO()
			spneg.add_auth_context('MS KRB5 - Microsoft Kerberos 5', handler)
			return spneg
			
		elif creds.authentication_type == SMBCredentialsAuthType.SSPI_KERBEROS:
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
		
		elif creds.authentication_type == SMBCredentialsAuthType.SSPI_NTLM:
			ntlmcred = SMBNTLMSSPICredential()
			ntlmcred.client = creds.username #here we could submit the domain as well for impersonation? TODO!
			ntlmcred.password = creds.secret
			
			handler = SMBNTLMSSPI(ntlmcred)
			#setting up SPNEGO
			spneg = SPNEGO()
			spneg.add_auth_context('NTLMSSP - Microsoft NTLM Security Support Provider', handler)
			return spneg
		