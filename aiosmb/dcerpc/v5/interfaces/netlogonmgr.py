import os

from aiosmb.dcerpc.v5 import nrpc
from aiosmb.dcerpc.v5.interfaces.endpointmgr import EPM
from aiosmb.dcerpc.v5.common.connection.target import DCERPCTarget
from aiosmb.dcerpc.v5.common.connection.authentication import DCERPCAuth
from aiosmb.dcerpc.v5.connection import DCERPC5Connection
from aiosmb.dcerpc.v5.rpcrt import (
	RPC_C_AUTHN_LEVEL_NONE,
	RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,
	RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
)

# Negotiate-flag presets observed from a Windows 10 client.
# AES preset advertises NETLOGON_NEG_SUPPORTS_AES (0x01000000) so the channel
# uses HMAC-SHA256 / AES128-CFB8 for signing+sealing. The strong-key preset
# clears that bit and falls back to HMAC-MD5 / RC4.
NETLOGON_FLAGS_AES        = 0x612fffff
NETLOGON_FLAGS_STRONGKEY  = 0x212fffff


class SMBNetlogon:
	"""
	Helper that establishes a Netlogon secure channel (schannel) and exposes a
	ready-to-use DCE/RPC connection authenticated with RPC_C_AUTHN_NETLOGON.

	Typical usage::

		nl = await SMBNetlogon.from_smbconnection(
			connection, dc_name='DC01', computer_name='WS01',
			domain_name='CONTOSO', nt_hash=bytes.fromhex('...'))
		resp, err = await nrpc.hNetrLogonGetCapabilities(
			nl.dce, nl.dc_handle, nl.computer_name + '\\x00', nl.update_authenticator(), 0, 1)
		await nl.close()

	Note: the secure channel is carried over ncacn_ip_tcp (the named-pipe
	transport over a user SMB session is rejected by the DC for schannel).
	"""

	def __init__(self):
		self.dce = None              # the schannel-authenticated DCERPC5Connection
		self.session_key = None
		self.client_credential = None  # clientStoredCredential, used for authenticators
		self.computer_name = None
		self.domain_name = None
		self.dc_name = None
		self.aes = True
		self.negotiate_flags = None
		self._handshake_dce = None   # kept open for the lifetime of the channel

	@property
	def dc_handle(self):
		return '\\\\' + (self.dc_name or '') + '\x00'

	def update_authenticator(self):
		"""Returns a fresh NETLOGON_AUTHENTICATOR for the next authenticated call.

		The stored credential stays constant for the lifetime of the channel; the
		per-call freshness comes from the (strictly increasing) timestamp. Issue at
		most one authenticated call per second to avoid a duplicate-timestamp
		rejection from the DC.
		"""
		if self.aes:
			return nrpc.ComputeNetlogonAuthenticatorAES(self.client_credential, self.session_key)
		return nrpc.ComputeNetlogonAuthenticator(self.client_credential, self.session_key)

	@staticmethod
	async def from_smbconnection(connection, dc_name, computer_name, domain_name,
								 nt_hash=None, aes=True,
								 channel_type=nrpc.NETLOGON_SECURE_CHANNEL_TYPE.WorkstationSecureChannel,
								 auth_level=RPC_C_AUTHN_LEVEL_PKT_PRIVACY):
		"""
		Establishes a secure channel using an existing (already logged-in) SMB
		connection to locate/reach the DC.

		:param dc_name: NetBIOS name of the domain controller (without trailing '$')
		:param computer_name: client computer account name (without trailing '$')
		:param domain_name: NetBIOS domain name the computer account belongs to
		:param nt_hash: NT hash of the computer account password (shared secret)
		:param aes: use AES (HMAC-SHA256/AES128). If False, uses RC4/HMAC-MD5.
		:param channel_type: NETLOGON_SECURE_CHANNEL_TYPE (Workstation/Server/...)
		:param auth_level: RPC_C_AUTHN_LEVEL_PKT_PRIVACY (seal) or _PKT_INTEGRITY (sign)
		"""
		self = SMBNetlogon()
		self.computer_name = computer_name
		self.domain_name = domain_name
		self.dc_name = dc_name
		self.aes = aes

		# Map the netlogon endpoint over ncacn_ip_tcp.
		epm = EPM.from_smbconnection(connection, protocol='ncacn_ip_tcp')
		_, err = await epm.connect()
		if err is not None:
			return None, err
		string_binding, err = await epm.map(nrpc.MSRPC_UUID_NRPC)
		if err is not None:
			return None, err
		await epm.disconnect()

		dce_target = DCERPCTarget.from_connection_string(
			string_binding, dc_ip=connection.target.dc_ip, domain=connection.target.domain)

		try:
			_, err = await self._establish(dce_target, connection.gssapi, nt_hash, channel_type, auth_level)
			if err is not None:
				await self.close()
				return None, err
			return self, None
		except Exception as e:
			await self.close()
			return None, e

	async def _establish(self, dce_target, smb_gssapi, nt_hash, channel_type, auth_level):
		# --- handshake connection (plain bind), kept open for the channel lifetime
		hs = DCERPC5Connection(DCERPCAuth.from_smb_gssapi(smb_gssapi), dce_target)
		hs.set_auth_level(RPC_C_AUTHN_LEVEL_NONE)
		_, err = await hs.connect()
		if err is not None:
			return None, err
		_, err = await hs.bind(nrpc.MSRPC_UUID_NRPC)
		if err is not None:
			return None, err
		self._handshake_dce = hs

		dc_handle = self.dc_handle
		client_challenge = os.urandom(8)
		resp, err = await nrpc.hNetrServerReqChallenge(hs, dc_handle, self.computer_name + '\x00', client_challenge)
		if err is not None:
			return None, err
		server_challenge = bytes(resp['ServerChallenge'])

		flags = NETLOGON_FLAGS_AES if self.aes else NETLOGON_FLAGS_STRONGKEY
		if self.aes:
			self.session_key = nrpc.ComputeSessionKeyAES(None, client_challenge, server_challenge, sharedSecretHash=nt_hash)
			client_cred = nrpc.ComputeNetlogonCredentialAES(client_challenge, self.session_key)
			expected_server_cred = nrpc.ComputeNetlogonCredentialAES(server_challenge, self.session_key)
		else:
			self.session_key = nrpc.ComputeSessionKeyStrongKey(None, client_challenge, server_challenge, sharedSecretHash=nt_hash)
			client_cred = nrpc.ComputeNetlogonCredential(client_challenge, self.session_key)
			expected_server_cred = nrpc.ComputeNetlogonCredential(server_challenge, self.session_key)

		resp, err = await nrpc.hNetrServerAuthenticate3(
			hs, dc_handle, self.computer_name + '$\x00', channel_type,
			self.computer_name + '\x00', client_cred, flags)
		if err is not None:
			return None, err

		self.negotiate_flags = resp['NegotiateFlags']
		if bytes(resp['ServerCredential']) != expected_server_cred:
			return None, Exception('Netlogon server credential mismatch - secure channel not trusted')
		self.client_credential = client_cred

		# --- fresh schannel connection (sign/seal) on a separate TCP connection
		sch = DCERPC5Connection(DCERPCAuth.from_smb_gssapi(smb_gssapi), dce_target)
		sch.set_auth_level(auth_level)
		sch.set_netlogon_session_key(self.session_key, self.computer_name, self.domain_name, aes=self.aes)
		_, err = await sch.connect()
		if err is not None:
			return None, err
		_, err = await sch.bind(nrpc.MSRPC_UUID_NRPC)
		if err is not None:
			return None, err
		self.dce = sch
		return True, None

	async def close(self):
		if self.dce is not None:
			await self.dce.disconnect()
			self.dce = None
		if self._handshake_dce is not None:
			await self._handshake_dce.disconnect()
			self._handshake_dce = None

	async def __aenter__(self):
		return self

	async def __aexit__(self, exc_type, exc, tb):
		await self.close()
