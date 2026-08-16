from __future__ import annotations

import pytest
from asyauth.common.constants import asyauthSecret
from asyauth.common.credentials.ntlm import NTLMCredential
from asyauth.common.credentials.spnego import SPNEGOCredential
from asyauth.protocols.ntlm.structures.negotiate_flags import NegotiateFlags

from aiosmb.server.authentication import (
    SMBNTLMAuthenticator,
    anonymous_authenticator_factory,
)
from aiosmb.server.server import SMBServerSettings


pytestmark = [pytest.mark.component, pytest.mark.asyncio]


async def exchange(client, server):
    token, _, err = await client.authenticate(None, spn="cifs/server")
    assert err is None
    challenge, more, err = await server.authenticate_server(token)
    assert err is None
    assert more is True
    token, _, err = await client.authenticate(challenge, spn="cifs/server")
    assert err is None
    return await server.authenticate_server(token)


async def test_valid_ntlm_credentials_derive_the_client_session_key() -> None:
    credential = NTLMCredential(
        "correct horse",
        "alice",
        "LAB",
        stype=asyauthSecret.PASSWORD,
    )
    client = SPNEGOCredential([credential]).build_context()
    server = SMBNTLMAuthenticator(credential)

    _, more, err = await exchange(client, server)
    assert err is None
    assert more is False
    finished, err = await server.authenticate_server_finished()
    assert err is None
    _, _, err = await client.authenticate(finished, spn="cifs/server")
    assert err is None
    assert server.get_session_key() == client.get_session_key()
    captured = server.get_ntlm_hash()
    fields = captured.split(":")
    assert fields[:3] == ["alice", "", "LAB"]
    assert len(fields[3]) == 16
    assert len(fields[4]) == 32
    assert len(fields[5]) > 32


async def test_invalid_ntlm_password_is_rejected() -> None:
    server_credential = NTLMCredential(
        "right",
        "alice",
        "LAB",
        stype=asyauthSecret.PASSWORD,
    )
    client_credential = NTLMCredential(
        "wrong",
        "alice",
        "LAB",
        stype=asyauthSecret.PASSWORD,
    )
    client = SPNEGOCredential([client_credential]).build_context()
    server = SMBNTLMAuthenticator(server_credential)

    response, more, err = await exchange(client, server)
    assert response is None
    assert more is False
    assert isinstance(err, PermissionError)
    assert server.get_session_key() is None
    assert server.get_ntlm_hash() is None


async def test_anonymous_ntlm_session_is_accepted_without_credentials() -> None:
    client = SPNEGOCredential(
        [NTLMCredential.create_anonymous()]
    ).build_context()
    server = anonymous_authenticator_factory()()

    _, more, err = await exchange(client, server)

    assert err is None
    assert more is False
    assert server.is_anonymous() is True
    assert server.get_session_key() == b"\x00" * 16
    assert server.get_ntlm_hash() is None
    assert server.credential.stype is asyauthSecret.NONE


async def test_server_setting_clears_ess_from_ntlm_challenge() -> None:
    client_credential = NTLMCredential(
        "secret",
        "alice",
        "LAB",
        stype=asyauthSecret.PASSWORD,
    )
    client = SPNEGOCredential([client_credential]).build_context()
    settings = SMBServerSettings.from_password(
        "alice",
        "secret",
        "LAB",
        disable_ess=True,
    )
    server = settings.create_new_gssapi(object())

    token, _, err = await client.authenticate(None, spn="cifs/server")
    assert err is None
    _, more, err = await server.authenticate_server(token)

    assert err is None
    assert more is True
    flags = (
        server._spnego.selected_authentication_context_server
        .ntlmChallenge.NegotiateFlags
    )
    assert NegotiateFlags.NEGOTIATE_EXTENDED_SESSIONSECURITY not in flags
