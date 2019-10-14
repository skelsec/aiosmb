import unittest

from aiosmb.ntlm.structures.negotiate_flags import NegotiateFlags
from aiosmb.ntlm.structures.version import *
from aiosmb.ntlm.native import *


class TestNTLMv1ESS(unittest.TestCase):
	def setUp(self):
		self.credential = Credential()
		self.credential.username = 'User'
		self.credential.domain = 'Domain'
		self.credential.password = 'Password'
		
		self.template = {
				'flags'            :  NegotiateFlags.NEGOTIATE_56|
									  NegotiateFlags.NEGOTIATE_VERSION|
									  NegotiateFlags.NEGOTIATE_EXTENDED_SESSIONSECURITY|
									  NegotiateFlags.TARGET_TYPE_SERVER|
									  NegotiateFlags.NEGOTIATE_ALWAYS_SIGN|
									  NegotiateFlags.TARGET_TYPE_SERVER|
									  NegotiateFlags.NEGOTIATE_ALWAYS_SIGN|
									  NegotiateFlags.NEGOTIATE_NTLM|
									  NegotiateFlags.NEGOTIATE_SIGN|
									  NegotiateFlags.NEGOTIATE_SEAL|
									  NegotiateFlags.NTLM_NEGOTIATE_OEM|
									  NegotiateFlags.NEGOTIATE_UNICODE,
				'challenge'        : b'\xaa' * 8,
				'session_key'      : b'\x55'*16,
				'version'          : Version.construct(WindowsMajorVersion.WINDOWS_MAJOR_VERSION_10, minor = WindowsMinorVersion.WINDOWS_MINOR_VERSION_0, build = 15063 ),
				'domain_name'      : 'Domain',
				'workstation_name' : 'COMPUTER',
				'ntlm_downgrade'   : True,
		}
		
		


	def test_msdn_example_ntlmv1ESS(self):
		settings = NTLMHandlerSettings(self.credential, mode = 'CLIENT', template_name = None, ntlm_downgrade = True, custom_template = self.template)
		handler = NTLMAUTHHandler(settings)
		data, is_res = handler.authenticate(None)		
		details = AVPairs({AVPAIRType.MsvAvNbDomainName: 'TEST', AVPAIRType.MsvAvNbComputerName: 'WIN2019AD', AVPAIRType.MsvAvDnsDomainName: 'test.corp', AVPAIRType.MsvAvDnsComputerName: 'WIN2019AD.test.corp', AVPAIRType.MsvAvTimestamp: b'\xae\xc6\x00\xbf\xc5\xfd\xd4\x01', AVPAIRType.MsvAvFlags: b'\x02\x00\x00\x00', AVPAIRType.MsvAvSingleHost: b"0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00 \x00\x00R}'\xf24\xdet7`\x96c\x84\xd3oa\xae*\xa4\xfc*8\x06\x99\xf8\xca\xa6\x00\x01\x1bHm\x89", AVPAIRType.MsvChannelBindings: b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', AVPAIRType.MsvAvTargetName: 'cifs/10.10.10.2'})
		
		challenge = NTLMChallenge.construct(challenge=b'\x01\x23\x45\x67\x89\xab\xcd\xef', targetName = 'Domain', targetInfo = details, version = handler.ntlmNegotiate.Version, flags= handler.flags)
		data, is_res = handler.authenticate(challenge.to_bytes())
		
		self.assertEqual(handler.ntlmAuthenticate.LMChallenge.to_bytes(), bytes.fromhex('aaaaaaaaaaaaaaaa00000000000000000000000000000000'))
		self.assertEqual(handler.ntlmAuthenticate.NTChallenge.to_bytes(), bytes.fromhex('7537f803ae367128ca458204bde7caf81e97ed2683267232'))
		
		
		self.assertEqual(handler.SessionBaseKey, bytes.fromhex('d87262b0cde4b1cb7499becccdf10784'))
		self.assertEqual(handler.KeyExchangeKey, bytes.fromhex('eb93429a8bd952f8b89c55b87f475edc'))
		
		
		#CHALLENGE #bytes.fromhex('4e544c4d53535000020000000c000c003800000033820a820123456789abcdef00000000000000000000000000000000060070170000000f530065007200760065007200')
		
		

if __name__ == '__main__':
	unittest.main()