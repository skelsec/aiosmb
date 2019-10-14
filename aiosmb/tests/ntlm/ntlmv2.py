import unittest

from aiosmb.ntlm.structures.negotiate_flags import NegotiateFlags
from aiosmb.ntlm.structures.version import *
from aiosmb.ntlm.native import *


class TestNTLMv2(unittest.TestCase):
	def setUp(self):
		self.credential = Credential()
		self.credential.username = 'User'
		self.credential.domain = 'Domain'
		self.credential.password = 'Password'
		
		#									  NegotiateFlags.NEGOTIATE_VERSION|
		#'version'          : Version.construct(WindowsMajorVersion.WINDOWS_MAJOR_VERSION_10, minor = WindowsMinorVersion.WINDOWS_MINOR_VERSION_0, build = 15063 ),
		self.template = {
				'flags'            :  NegotiateFlags.NEGOTIATE_56|
									  NegotiateFlags.NEGOTIATE_128|
									  NegotiateFlags.NEGOTIATE_KEY_EXCH|
									  NegotiateFlags.REQUEST_TARGET|
									  NegotiateFlags.NEGOTIATE_EXTENDED_SESSIONSECURITY|
									  NegotiateFlags.TARGET_TYPE_SERVER|
									  NegotiateFlags.NEGOTIATE_ALWAYS_SIGN|
									  NegotiateFlags.NEGOTIATE_NTLM|
									  NegotiateFlags.NEGOTIATE_SIGN|
									  NegotiateFlags.NEGOTIATE_SEAL|
									  NegotiateFlags.NTLM_NEGOTIATE_OEM|
									  NegotiateFlags.NEGOTIATE_UNICODE,
				'challenge'        : b'\xaa' * 8,
				'session_key'      : b'\x55' * 16,
				'timestamp'        : datetime.datetime(1601, 1, 1),
				'domain_name'      : 'Domain',
				'workstation_name' : 'COMPUTER',
				'ntlm_downgrade'   : False,
		}
		
		
	#NetBIOS Server name: Server
	#NetBIOS Domain name: Domain

	def test_msdn_example_ntlmv2(self):
		"""
		IMPORTANT!!!
		This test cannot be automated currently!
		You must manually change the timestamp to b'\x00'*8 in the NTLMv2ClientChallenge object!!!!
		"""	
	
		settings = NTLMHandlerSettings(self.credential, mode = 'CLIENT', template_name = None, ntlm_downgrade = False, custom_template = self.template)
		handler = NTLMAUTHHandler(settings)
		data, is_res = handler.authenticate(None)		
		details = AVPairs({AVPAIRType.MsvAvNbDomainName: 'Domain', AVPAIRType.MsvAvNbComputerName: 'Server'})
		
		challenge = NTLMChallenge.construct(challenge=b'\x01\x23\x45\x67\x89\xab\xcd\xef', targetName = 'Domain', targetInfo = details, flags= handler.flags)
		
		challenge_data_msdn = bytes.fromhex('4e544c4d53535000020000000c000c003800000033828ae20123456789abcdef00000000000000002400240044000000060070170000000f53006500720076006500720002000c0044006f006d00610069006e0001000c0053006500720076006500720000000000')
		#data, is_res = handler.authenticate(challenge_data_msdn)
		data, is_res = handler.authenticate(challenge.to_bytes())
		
		self.assertEqual(handler.ntlmAuthenticate.LMChallenge.to_bytes(), bytes.fromhex('86 c3 50 97 ac 9c ec 10 25 54 76 4a 57 cc cc 19 aa aa aa aa aa aa aa aa'))
		self.assertEqual(handler.ntlmAuthenticate.NTChallenge.Response, bytes.fromhex('68 cd 0a b8 51 e5 1c 96 aa bc 92 7b eb ef 6a 1c'))
		
		
		self.assertEqual(handler.SessionBaseKey, bytes.fromhex('8de40ccadbc14a82f15cb0ad0de95ca3'))
		self.assertEqual(handler.KeyExchangeKey, bytes.fromhex('8de40ccadbc14a82f15cb0ad0de95ca3')) #same as sessionbasekey
		self.assertEqual(handler.EncryptedRandomSessionKey, bytes.fromhex('c5 da d2 54 4f c9 79 90 94 ce 1c e9 0b c9 d0 3e'))
		
		
		#CHALLENGE #bytes.fromhex('4e544c4d53535000020000000c000c003800000033820a820123456789abcdef00000000000000000000000000000000060070170000000f530065007200760065007200')
		
		

if __name__ == '__main__':
	unittest.main()