import unittest

from aiosmb.ntlm.structures.negotiate_flags import NegotiateFlags
from aiosmb.ntlm.structures.version import *
from aiosmb.ntlm.auth_handler import *


class TestNTLMv1(unittest.TestCase):
	def setUp(self):
		self.credential = Credential()
		self.credential.username = 'User'
		self.credential.domain = 'Domain'
		self.credential.password = 'Password'
		
		self.template_non_nt_session_key = {
				'flags'            :  NegotiateFlags.NEGOTIATE_56|
									  NegotiateFlags.REQUEST_NON_NT_SESSION_KEY|
									  NegotiateFlags.NEGOTIATE_KEY_EXCH|
									  NegotiateFlags.NEGOTIATE_128|
									  NegotiateFlags.NEGOTIATE_VERSION|
									  NegotiateFlags.TARGET_TYPE_SERVER|
									  NegotiateFlags.NEGOTIATE_ALWAYS_SIGN|
									  NegotiateFlags.NEGOTIATE_NTLM|
									  NegotiateFlags.NEGOTIATE_SIGN|
									  NegotiateFlags.NEGOTIATE_SEAL|
									  NegotiateFlags.NTLM_NEGOTIATE_OEM|
									  NegotiateFlags.NEGOTIATE_UNICODE,
				'session_key'      : b'\x55'*16,
				'version'          : Version.construct(WindowsMajorVersion.WINDOWS_MAJOR_VERSION_10, minor = WindowsMinorVersion.WINDOWS_MINOR_VERSION_0, build = 15063 ),
				'domain_name'      : 'Domain',
				'workstation_name' : 'COMPUTER',
				'ntlm_downgrade'   : True,
				'extended_security': False
		}
		
		self.template_lm_key = {
				'flags'            :  NegotiateFlags.NEGOTIATE_56|
									  NegotiateFlags.NEGOTIATE_LM_KEY|
									  NegotiateFlags.NEGOTIATE_KEY_EXCH|
									  NegotiateFlags.NEGOTIATE_128|
									  NegotiateFlags.NEGOTIATE_VERSION|
									  NegotiateFlags.TARGET_TYPE_SERVER|
									  NegotiateFlags.NEGOTIATE_ALWAYS_SIGN|
									  NegotiateFlags.NEGOTIATE_NTLM|
									  NegotiateFlags.NEGOTIATE_SIGN|
									  NegotiateFlags.NEGOTIATE_SEAL|
									  NegotiateFlags.NTLM_NEGOTIATE_OEM|
									  NegotiateFlags.NEGOTIATE_UNICODE,
				'session_key'      : b'\x55'*16,
				'version'          : Version.construct(WindowsMajorVersion.WINDOWS_MAJOR_VERSION_10, minor = WindowsMinorVersion.WINDOWS_MINOR_VERSION_0, build = 15063 ),
				'domain_name'      : 'Domain',
				'workstation_name' : 'COMPUTER',
				'ntlm_downgrade'   : True,
				'extended_security': False
		}
		
		self.template_no_flags = {
				'flags'            :  NegotiateFlags.NEGOTIATE_56|
									  NegotiateFlags.NEGOTIATE_KEY_EXCH|
									  NegotiateFlags.NEGOTIATE_128|
									  NegotiateFlags.NEGOTIATE_VERSION|
									  NegotiateFlags.TARGET_TYPE_SERVER|
									  NegotiateFlags.NEGOTIATE_ALWAYS_SIGN|
									  NegotiateFlags.NEGOTIATE_NTLM|
									  NegotiateFlags.NEGOTIATE_SIGN|
									  NegotiateFlags.NEGOTIATE_SEAL|
									  NegotiateFlags.NTLM_NEGOTIATE_OEM|
									  NegotiateFlags.NEGOTIATE_UNICODE,
				'session_key'      : b'\x55'*16,
				'version'          : Version.construct(WindowsMajorVersion.WINDOWS_MAJOR_VERSION_10, minor = WindowsMinorVersion.WINDOWS_MINOR_VERSION_0, build = 15063 ),
				'domain_name'      : 'Domain',
				'workstation_name' : 'COMPUTER',
				'ntlm_downgrade'   : True,
		}
		
		


	def test_msdn_example_non_nt_session_key(self):
		settings = NTLMHandlerSettings(self.credential, mode = 'CLIENT', template_name = None, ntlm_downgrade = True, custom_template = self.template_non_nt_session_key)
		handler = NTLMAUTHHandler(settings)
		data, is_res = handler.authenticate(None)		
		details = AVPairs({AVPAIRType.MsvAvNbDomainName: 'TEST', AVPAIRType.MsvAvNbComputerName: 'WIN2019AD', AVPAIRType.MsvAvDnsDomainName: 'test.corp', AVPAIRType.MsvAvDnsComputerName: 'WIN2019AD.test.corp', AVPAIRType.MsvAvTimestamp: b'\xae\xc6\x00\xbf\xc5\xfd\xd4\x01', AVPAIRType.MsvAvFlags: b'\x02\x00\x00\x00', AVPAIRType.MsvAvSingleHost: b"0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00 \x00\x00R}'\xf24\xdet7`\x96c\x84\xd3oa\xae*\xa4\xfc*8\x06\x99\xf8\xca\xa6\x00\x01\x1bHm\x89", AVPAIRType.MsvChannelBindings: b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', AVPAIRType.MsvAvTargetName: 'cifs/10.10.10.2'})
		
		challenge = NTLMChallenge.construct(challenge=b'\x01\x23\x45\x67\x89\xab\xcd\xef', targetName = 'Domain', targetInfo = details, version = handler.ntlmNegotiate.Version, flags= handler.flags)
		data, is_res = handler.authenticate(challenge.to_bytes())
		
		self.assertEqual(handler.ntlmAuthenticate.NTChallenge.to_bytes(), bytes.fromhex('67c43011f30298a2ad35ece64f16331c44bdbed927841f94'))
		self.assertEqual(handler.ntlmAuthenticate.LMChallenge.to_bytes(), bytes.fromhex('98def7b87f88aa5dafe2df779688a172def11c7d5ccdef13'))
		
		self.assertEqual(handler.EncryptedRandomSessionKey, bytes.fromhex('7452ca55c225a1ca04b48fae32cf56fc'))
		
	def test_msdn_example_lm_key(self):
		settings = NTLMHandlerSettings(self.credential, mode = 'CLIENT', template_name = None, ntlm_downgrade = True, custom_template = self.template_lm_key)
		handler = NTLMAUTHHandler(settings)
		data, is_res = handler.authenticate(None)		
		details = AVPairs({AVPAIRType.MsvAvNbDomainName: 'TEST', AVPAIRType.MsvAvNbComputerName: 'WIN2019AD', AVPAIRType.MsvAvDnsDomainName: 'test.corp', AVPAIRType.MsvAvDnsComputerName: 'WIN2019AD.test.corp', AVPAIRType.MsvAvTimestamp: b'\xae\xc6\x00\xbf\xc5\xfd\xd4\x01', AVPAIRType.MsvAvFlags: b'\x02\x00\x00\x00', AVPAIRType.MsvAvSingleHost: b"0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00 \x00\x00R}'\xf24\xdet7`\x96c\x84\xd3oa\xae*\xa4\xfc*8\x06\x99\xf8\xca\xa6\x00\x01\x1bHm\x89", AVPAIRType.MsvChannelBindings: b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', AVPAIRType.MsvAvTargetName: 'cifs/10.10.10.2'})
		
		challenge = NTLMChallenge.construct(challenge=b'\x01\x23\x45\x67\x89\xab\xcd\xef', targetName = 'Domain', targetInfo = details, version = handler.ntlmNegotiate.Version, flags= handler.flags)
		data, is_res = handler.authenticate(challenge.to_bytes())	
		
		self.assertEqual(handler.ntlmAuthenticate.NTChallenge.to_bytes(), bytes.fromhex('67c43011f30298a2ad35ece64f16331c44bdbed927841f94'))
		self.assertEqual(handler.KeyExchangeKey, bytes.fromhex('b09e379f7fbecb1eaf0afdcb0383c8a0'))
		
		self.assertEqual(handler.EncryptedRandomSessionKey, bytes.fromhex('4cd7bb57d697ef9b549f02b8f9b37864'))
		
	def test_msdn_example_no_flags(self):
		settings = NTLMHandlerSettings(self.credential, mode = 'CLIENT', template_name = None, ntlm_downgrade = True, custom_template = self.template_no_flags)
		handler = NTLMAUTHHandler(settings)
		data, is_res = handler.authenticate(None)		
		details = AVPairs({AVPAIRType.MsvAvNbDomainName: 'TEST', AVPAIRType.MsvAvNbComputerName: 'WIN2019AD', AVPAIRType.MsvAvDnsDomainName: 'test.corp', AVPAIRType.MsvAvDnsComputerName: 'WIN2019AD.test.corp', AVPAIRType.MsvAvTimestamp: b'\xae\xc6\x00\xbf\xc5\xfd\xd4\x01', AVPAIRType.MsvAvFlags: b'\x02\x00\x00\x00', AVPAIRType.MsvAvSingleHost: b"0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00 \x00\x00R}'\xf24\xdet7`\x96c\x84\xd3oa\xae*\xa4\xfc*8\x06\x99\xf8\xca\xa6\x00\x01\x1bHm\x89", AVPAIRType.MsvChannelBindings: b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', AVPAIRType.MsvAvTargetName: 'cifs/10.10.10.2'})
		
		challenge = NTLMChallenge.construct(challenge=b'\x01\x23\x45\x67\x89\xab\xcd\xef', targetName = 'Domain', targetInfo = details, version = handler.ntlmNegotiate.Version, flags= handler.flags)
		data, is_res = handler.authenticate(challenge.to_bytes())
		
		self.assertEqual(handler.ntlmAuthenticate.NTChallenge.to_bytes(), bytes.fromhex('67c43011f30298a2ad35ece64f16331c44bdbed927841f94'))
		
		self.assertEqual(handler.EncryptedRandomSessionKey, bytes.fromhex('518822b1b3f350c8958682ecbb3e3cb7'))
		

if __name__ == '__main__':
	unittest.main()