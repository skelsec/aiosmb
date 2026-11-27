import asyncio
import hashlib
import hmac
import secrets

from asyauth.common.constants import asyauthSecret
from asyauth.common.credentials.ntlm import NTLMCredential
from asyauth.protocols.ntlm.creds_calc import NTOWFv2
from asyauth.protocols.ntlm.server.native import ntlmserver_factory
from asyauth.protocols.ntlm.structures.negotiate_flags import NegotiateFlags
from asyauth.protocols.spnego.server.native import spnegoserver_ntlm_factory
from unicrypto.symmetric import RC4


class SMBNTLMAuthenticator:
	"""Credential-validating SPNEGO/NTLM server facade.

	The generic asyauth native server is also used for capture/relay scenarios and
	does not validate the final NTLMv2 proof.  A file server must validate that
	proof before exposing a share, so this adapter performs the server-side check
	and derives the exported session key used by SMB2 signing.
	"""

	def __init__(self, credential):
		self.credential = credential
		self._session_key = None
		self._ntlm_hash = None
		self._spnego = spnegoserver_ntlm_factory(
			asyncio.Queue(),
			lambda: ntlmserver_factory(lambda: credential),
		)

	def set_connection_info(self, connection):
		self._spnego.set_connection_info(connection)

	def get_mechtypes_list(self):
		return self._spnego.get_mechtypes_list()

	async def authenticate_server(self, token):
		response, to_continue, err = await self._spnego.authenticate_server(token)
		if err is not None or to_continue:
			return response, to_continue, err
		try:
			self._validate_final_authentication()
			return response, False, None
		except Exception as e:
			return None, False, e

	async def authenticate_server_finished(self):
		return await self._spnego.authenticate_server_finished()

	def get_session_key(self):
		return self._session_key

	def get_ntlm_hash(self):
		return self._ntlm_hash

	def is_anonymous(self):
		return bool(
			getattr(self.credential, 'is_anonymous', False)
			and getattr(self, '_authenticated_username', None) == ''
		)

	def _response_key(self, username, domain):
		if self.credential.stype == asyauthSecret.PASSWORD:
			return NTOWFv2(
				self.credential.secret,
				username,
				domain,
			)
		if self.credential.stype in (asyauthSecret.NT, asyauthSecret.RC4):
			return NTOWFv2(
				None,
				username,
				domain,
				bytes.fromhex(self.credential.secret),
			)
		raise ValueError('NTLM server credentials must use a password or NT hash')

	def _validate_final_authentication(self):
		self._ntlm_hash = None
		context = self._spnego.selected_authentication_context_server
		if context is None or context.ntlmAuthenticate is None:
			raise PermissionError('NTLM authentication did not produce an authenticate message')
		authenticate = context.ntlmAuthenticate
		username = authenticate.UserName
		domain = authenticate.DomainName
		self._authenticated_username = username
		if not username:
			if not self.credential.is_guest:
				raise PermissionError('Guest authentication is disabled')
			self._session_key = b'\x00' * 16
			self._ntlm_hash = None
			return
		if username.casefold() != self.credential.username.casefold():
			raise PermissionError('Unknown NTLM user')
		configured_domain = self.credential.domain or ''
		if configured_domain and domain.casefold() != configured_domain.casefold():
			raise PermissionError('Unknown NTLM domain')
		if authenticate.NTChallenge is None:
			raise PermissionError('NTLMv2 response is required')

		field = authenticate.NtChallengeResponseFields
		nt_response = context.ntlmAuthenticate_raw[
			field.offset:field.offset + field.length
		]
		if len(nt_response) < 17:
			raise PermissionError('Truncated NTLMv2 response')
		proof = nt_response[:16]
		client_challenge = nt_response[16:]
		response_key = self._response_key(username, domain)
		expected = hmac.new(
			response_key,
			context.ntlmChallenge.ServerChallenge + client_challenge,
			hashlib.md5,
		).digest()
		if not secrets.compare_digest(proof, expected):
			raise PermissionError('Invalid NTLM credentials')
		self._ntlm_hash = '%s::%s:%s:%s:%s' % (
			username,
			domain,
			context.ntlmChallenge.ServerChallenge.hex(),
			proof.hex(),
			client_challenge.hex(),
		)

		session_base_key = hmac.new(
			response_key,
			proof,
			hashlib.md5,
		).digest()
		if (
			authenticate.NegotiateFlags & NegotiateFlags.NEGOTIATE_KEY_EXCH
			and authenticate.EncryptedRandomSession
		):
			session_key = RC4(session_base_key).decrypt(
				authenticate.EncryptedRandomSession
			)
		else:
			session_key = session_base_key
		if len(session_key) != 16:
			raise PermissionError('Invalid NTLM exported session key')
		self._session_key = session_key
		context.SessionBaseKey = session_base_key
		context.KeyExchangeKey = session_base_key
		context.RandomSessionKey = session_key


def ntlm_authenticator_factory(password, username, domain=''):
	credential = NTLMCredential(
		password,
		username,
		domain,
		stype=asyauthSecret.PASSWORD,
	)
	return lambda: SMBNTLMAuthenticator(credential)


def ntlm_hash_authenticator_factory(nt_hash, username, domain=''):
	credential = NTLMCredential(
		nt_hash,
		username,
		domain,
		stype=asyauthSecret.NT,
	)
	return lambda: SMBNTLMAuthenticator(credential)


def anonymous_authenticator_factory():
	credential = NTLMCredential(
		None,
		'',
		'',
		stype=asyauthSecret.NONE,
	)
	return lambda: SMBNTLMAuthenticator(credential)
