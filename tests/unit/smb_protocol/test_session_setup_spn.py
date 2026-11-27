import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from asyauth.common.constants import asyauthSecret
from asyauth.common.credentials.ntlm import NTLMCredential
from asyauth.common.credentials.spnego import SPNEGOCredential
from asyauth.protocols.ntlm.messages.authenticate import NTLMAuthenticate
from asyauth.protocols.ntlm.messages.challenge import NTLMChallenge
from asyauth.protocols.ntlm.structures.avpair import AVPAIRType
from asyauth.protocols.ntlm.structures.avpair import AVPairs
from asyauth.protocols.spnego.messages.asn1_structs import NegTokenResp
from asyauth.protocols.spnego.messages.asn1_structs import NegotiationToken
from minikerberos.common.spn import KerberosSPN

from aiosmb.commons.connection.target import SMBTarget
from aiosmb.connection import SMBConnection
from aiosmb.protocol.common import NegotiateDialects
from aiosmb.wintypes.ntstatus import NTStatus


NTLM = 'NTLMSSP - Microsoft NTLM Security Support Provider'
KERBEROS = 'MS KRB5 - Microsoft Kerberos 5'


def reply(status, token):
    return (
        SimpleNamespace(
            header=SimpleNamespace(Status=status, SessionId=1),
            command=SimpleNamespace(Buffer=token, SessionFlags=0),
        ),
        b'synthetic SMB reply',
        None,
    )


def prepare_connection(target, context, replies):
    connection = SMBConnection(context, target)
    connection.selected_dialect = NegotiateDialects.SMB210
    connection.sent_tokens = []

    async def send(message):
        connection.sent_tokens.append(message.command.Buffer)
        return 1, None

    connection.sendSMB = AsyncMock(side_effect=send)
    connection.recvSMB = AsyncMock(side_effect=replies)
    context.authenticate = AsyncMock(wraps=context.authenticate)
    return connection


@pytest.mark.parametrize('hostname', ['server', 'server.example.test', None])
@pytest.mark.parametrize('domain', ['EXAMPLE', None])
def test_ntlm_authenticate_target_name(hostname, domain):
    async def run():
        target = SMBTarget(ip='192.0.2.10', hostname=hostname, domain=domain)
        credential = NTLMCredential(
            'SyntheticPassword!', 'user', 'EXAMPLE', asyauthSecret.PASSWORD,
        )
        context = SPNEGOCredential([credential]).build_context()
        info = AVPairs()
        info[AVPAIRType.MsvAvNbDomainName] = 'EXAMPLE'
        info[AVPAIRType.MsvAvNbComputerName] = 'SERVER'
        challenge = NTLMChallenge.construct(
            challenge=b'12345678',
            targetName='EXAMPLE',
            targetInfo=info,
            flags=credential.flags,
            version=credential.negotiate_version,
        )
        challenge_token = NegotiationToken({
            'negTokenResp': NegTokenResp({
                'negState': 'accept-incomplete',
                'supportedMech': NTLM,
                'responseToken': challenge.to_bytes(),
            }),
        }).dump()
        completed_token = NegotiationToken({
            'negTokenResp': NegTokenResp({'negState': 'accept-completed'}),
        }).dump()
        connection = prepare_connection(target, context, [
            reply(NTStatus.MORE_PROCESSING_REQUIRED, challenge_token),
            reply(NTStatus.SUCCESS, completed_token),
        ])
        success, error = await connection.session_setup()
        assert error is None
        assert success
        wire_token = connection.sent_tokens[1]
        authenticate_token = NegotiationToken.load(wire_token).native['responseToken']
        authenticate = NTLMAuthenticate.from_bytes(authenticate_token)
        details = authenticate.NTChallenge.ChallengeFromClinet.Details
        target_name = details[AVPAIRType.MsvAvTargetName]
        expected = 'cifs/' + (hostname or '192.0.2.10')
        assert target_name == expected
        # Includes the final authenticate call after the server reports success.
        spns = [call.kwargs['spn'] for call in context.authenticate.call_args_list]
        assert spns == [expected] * 3

        # A fresh authentication context must make the same choice on reuse.
        connection.gssapi = connection.original_gssapi.get_copy()
        connection.recvSMB.side_effect = [
            reply(NTStatus.MORE_PROCESSING_REQUIRED, challenge_token),
            reply(NTStatus.SUCCESS, completed_token),
        ]
        success, error = await connection.session_setup()
        assert error is None
        assert success
        wire_token = connection.sent_tokens[-1]
        authenticate = NTLMAuthenticate.from_bytes(
            NegotiationToken.load(wire_token).native['responseToken'],
        )
        details = authenticate.NTChallenge.ChallengeFromClinet.Details
        assert details[AVPAIRType.MsvAvTargetName] == expected

    asyncio.run(run())


@pytest.mark.parametrize('mechanism', [KERBEROS, 'KRB5 - Kerberos 5'])
def test_kerberos_keeps_realm_for_both_authenticate_calls(mechanism):
    async def run():
        target = SMBTarget(hostname='server.example.test', domain='EXAMPLE')
        parsed = []

        async def authenticate(token, spn=None, **kwargs):
            parsed.append(KerberosSPN.from_spn(spn))
            return b'synthetic Kerberos token', False, None

        context = SimpleNamespace(
            selected_authentication_context_name=mechanism,
            authentication_contexts={mechanism: object()},
            authenticate=authenticate,
            is_guest=lambda: False,
            get_session_key=lambda: b'0' * 16,
        )
        connection = prepare_connection(target, context, [reply(NTStatus.SUCCESS, b'')])
        success, error = await connection.session_setup()
        assert error is None
        assert success
        assert len(parsed) == 2
        for spn in parsed:
            assert (spn.service, spn.username, spn.domain) == (
                'cifs', 'server.example.test', 'EXAMPLE',
            )
        assert target.to_target_string() == 'cifs/server.example.test@EXAMPLE'

    asyncio.run(run())


@pytest.mark.parametrize(('selected', 'offered', 'expected'), [
    pytest.param(None, [NTLM], 'cifs/server.example.test', id='ntlm-before-selection'),
    pytest.param(NTLM, [NTLM, KERBEROS], 'cifs/server.example.test', id='selected-ntlm'),
    pytest.param(
        KERBEROS, [NTLM, KERBEROS], 'cifs/server.example.test@EXAMPLE', id='selected-kerberos',
    ),
    pytest.param(
        None, [KERBEROS], 'cifs/server.example.test@EXAMPLE', id='kerberos-before-selection',
    ),
    pytest.param(None, [NTLM, KERBEROS], 'cifs/server.example.test@EXAMPLE', id='undecided'),
    pytest.param(None, ['NEGOEX - SPNEGO Extended Negotiation Security Mechanism'],
                 'cifs/server.example.test@EXAMPLE', id='negoex'),
])
def test_spn_follows_current_spnego_mechanism(selected, offered, expected):
    context = SimpleNamespace(
        selected_authentication_context_name=selected,
        authentication_contexts=dict.fromkeys(offered),
    )
    target = SMBTarget(hostname='server.example.test', domain='EXAMPLE')
    connection = SMBConnection(context, target)
    assert connection._get_authentication_spn() == expected
    # Re-evaluate after SPNEGO selects a mechanism; do not cache the initial choice.
    context.selected_authentication_context_name = NTLM
    assert connection._get_authentication_spn() == 'cifs/server.example.test'
    context.selected_authentication_context_name = KERBEROS
    assert connection._get_authentication_spn() == target.to_target_string()


def test_custom_authentication_context_keeps_legacy_spn():
    target = SMBTarget(hostname='server.example.test', domain='EXAMPLE')
    connection = SMBConnection(object(), target)
    assert connection._get_authentication_spn() == target.to_target_string()
