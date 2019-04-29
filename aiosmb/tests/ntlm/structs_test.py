import unittest

from aiosmb.ntlm.structures.negotiate_flags import NegotiateFlags

class TestNegotiateFlags(unittest.TestCase):
	def test_msdn_example(self):
		flags = NegotiateFlags.NEGOTIATE_56|\
				NegotiateFlags.NEGOTIATE_KEY_EXCH|\
				NegotiateFlags.NEGOTIATE_128|\
				NegotiateFlags.NEGOTIATE_VERSION|\
				NegotiateFlags.TARGET_TYPE_SERVER|\
				NegotiateFlags.NEGOTIATE_ALWAYS_SIGN|\
				NegotiateFlags.NEGOTIATE_NTLM|\
				NegotiateFlags.NEGOTIATE_SIGN|\
				NegotiateFlags.NEGOTIATE_SEAL|\
				NegotiateFlags.NTLM_NEGOTIATE_OEM|\
				NegotiateFlags.NEGOTIATE_UNICODE
				
		self.assertEqual(flags, int.from_bytes(b'\x33\x82\x02\xe2', "little", signed = False))

if __name__ == '__main__':
	unittest.main()