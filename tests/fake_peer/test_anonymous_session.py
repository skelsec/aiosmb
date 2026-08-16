import pytest

from aiosmb.commons.exceptions import SMBAuthenticationFailed
from aiosmb.connection import SMBConnectionStatus
from aiosmb.protocol.common import NegotiateDialects
from aiosmb.protocol.smb2.command_codes import SMB2Command
from aiosmb.protocol.smb2.commands import SESSION_SETUP_REPLY
from aiosmb.protocol.smb2.commands.negotiate import NegotiateSecurityMode
from aiosmb.protocol.smb2.commands.sessionsetup import SessionFlags
from tests.support.smb_connection import make_connection, make_reply


pytestmark = [pytest.mark.fake_peer, pytest.mark.asyncio]


class ScriptedAuthenticator:
    def __init__(self, session_key=b"\x33" * 16):
        self.session_key = session_key
        self.calls = []

    async def authenticate(self, token, **kwargs):
        self.calls.append(token)
        if len(self.calls) == 1:
            return b"client-token", True, None
        return None, False, None

    def get_session_key(self):
        return self.session_key


def session_reply(flags):
    body = SESSION_SETUP_REPLY()
    body.SessionFlags = flags
    body.Buffer = b"server-finished"
    return make_reply(
        1,
        body,
        command=SMB2Command.SESSION_SETUP,
        session_id=7,
    )


async def run_session_setup(
    monkeypatch,
    flags,
    security_mode,
    session_key=b"\x33" * 16,
    dialect=NegotiateDialects.SMB202,
    supports_encryption=False,
):
    connection = make_connection(
        status=SMBConnectionStatus.SESSIONSETUP,
        dialect=dialect,
    )
    connection.ServerSecurityMode = security_mode
    connection.signing_required = bool(security_mode)
    connection.SupportsEncryption = supports_encryption
    connection.gssapi = ScriptedAuthenticator(session_key)
    reply = session_reply(flags)

    async def send_smb(_message):
        return 1, None

    async def recv_smb(_message_id):
        return reply, reply.to_bytes(), None

    monkeypatch.setattr(connection, "sendSMB", send_smb)
    monkeypatch.setattr(connection, "recvSMB", recv_smb)
    result, error = await connection.session_setup()
    return connection, result, error


@pytest.mark.parametrize(
    "flag,anonymous,guest",
    [
        (SessionFlags.SMB2_SESSION_FLAG_IS_NULL, True, False),
        (SessionFlags.SMB2_SESSION_FLAG_IS_GUEST, False, True),
    ],
)
async def test_restricted_session_flags_disable_keys_and_signing(
    monkeypatch, flag, anonymous, guest
) -> None:
    connection, result, error = await run_session_setup(
        monkeypatch,
        flag,
        NegotiateSecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED,
    )

    assert result is True
    assert error is None
    assert connection.is_anonymous is anonymous
    assert connection.is_guest is guest
    assert connection.SessionKey is None
    assert connection.signing_required is False
    assert connection.status is SMBConnectionStatus.RUNNING


async def test_normal_session_retains_session_key(monkeypatch) -> None:
    connection, result, error = await run_session_setup(
        monkeypatch,
        SessionFlags(0),
        NegotiateSecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED,
    )

    assert result is True
    assert error is None
    assert connection.is_anonymous is False
    assert connection.is_guest is False
    assert connection.SessionKey == b"\x33" * 16


async def test_normal_smb3_session_honors_required_encryption_flag(
    monkeypatch,
) -> None:
    connection, result, error = await run_session_setup(
        monkeypatch,
        SessionFlags.SMB2_SESSION_FLAG_ENCRYPT_DATA,
        NegotiateSecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED,
        dialect=NegotiateDialects.SMB311,
        supports_encryption=True,
    )

    assert result is True
    assert error is None
    assert connection.session_encryption_required is True
    assert connection.encryption_required is True
    assert connection.EncryptionKey is not None
    assert connection.DecryptionKey is not None


async def test_anonymous_session_rejects_required_signing(monkeypatch) -> None:
    connection, result, error = await run_session_setup(
        monkeypatch,
        SessionFlags.SMB2_SESSION_FLAG_IS_NULL,
        (
            NegotiateSecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED
            | NegotiateSecurityMode.SMB2_NEGOTIATE_SIGNING_REQUIRED
        ),
    )

    assert result is False
    assert isinstance(error, SMBAuthenticationFailed)
    assert "cannot satisfy required signing" in str(error)
    assert connection.status is SMBConnectionStatus.SESSIONSETUP


async def test_normal_session_rejects_missing_session_key(monkeypatch) -> None:
    connection, result, error = await run_session_setup(
        monkeypatch,
        SessionFlags(0),
        NegotiateSecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED,
        session_key=None,
    )

    assert result is False
    assert isinstance(error, SMBAuthenticationFailed)
    assert "did not produce a session key" in str(error)
    assert connection.status is SMBConnectionStatus.SESSIONSETUP
