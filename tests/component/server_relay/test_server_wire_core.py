from __future__ import annotations

import hashlib
import hmac
from typing import List

import pytest

from aiosmb.protocol.common import NegotiateDialects
from aiosmb.protocol.smb2.command_codes import SMB2Command
from aiosmb.protocol.smb2.commands import ECHO_REQ
from aiosmb.protocol.smb2.headers.common import SMB2HeaderFlag
from aiosmb.protocol.smb2.message import SMB2Message
from aiosmb.wintypes.ntstatus import NTStatus
from tests.component.server_relay.support import (
    FakeGSSAPI,
    FakeTransport,
    make_request,
)


pytestmark = [pytest.mark.component, pytest.mark.asyncio]


def make_connection(require_signing: bool = False):
    from aiosmb.server.server import SMBServerSettings
    from aiosmb.server.serverconnection import (
        SMBConnectionStatus,
        SMBServerConnection,
    )

    transport = FakeTransport()
    settings = SMBServerSettings(FakeGSSAPI, log_callback=None)
    settings.RequireSigning = require_signing
    connection = SMBServerConnection(settings, transport, 1)
    connection.status = SMBConnectionStatus.RUNNING
    connection.selected_dialect = NegotiateDialects.SMB202
    connection.SessionId = 1
    connection.SessionKey = b"\x22" * 16
    return connection, transport


def sign_request(message: SMB2Message, key: bytes) -> bytes:
    message.header.Flags |= SMB2HeaderFlag.SMB2_FLAGS_SIGNED
    message.header.Signature = b"\x00" * 16
    raw = message.to_bytes()
    signature = hmac.new(key, raw, hashlib.sha256).digest()[:16]
    message.header.Signature = signature
    return message.to_bytes()


def split_compound(packet: bytes) -> List[bytes]:
    result = []
    offset = 0
    while offset < len(packet):
        next_command = int.from_bytes(packet[offset + 20 : offset + 24], "little")
        end = offset + next_command if next_command else len(packet)
        result.append(packet[offset:end])
        if not next_command:
            break
        offset = end
    return result


async def test_signing_required_rejects_unsigned_request() -> None:
    connection, transport = make_connection(require_signing=True)
    request = make_request(ECHO_REQ(), SMB2Command.ECHO, message_id=9)

    await connection._handle_smb2_packet(request.to_bytes())

    response = SMB2Message.from_bytes(transport.writes[-1])
    assert response.header.MessageId == 9
    assert response.header.Status == NTStatus.ACCESS_DENIED
    assert response.header.Flags & SMB2HeaderFlag.SMB2_FLAGS_SIGNED
    connection.verify_message(response, transport.writes[-1])


async def test_signed_echo_is_verified_and_response_is_signed() -> None:
    connection, transport = make_connection(require_signing=True)
    request = make_request(ECHO_REQ(), SMB2Command.ECHO, message_id=10)

    await connection._handle_smb2_packet(
        sign_request(request, connection.SessionKey)
    )

    response = SMB2Message.from_bytes(transport.writes[-1])
    assert response.header.Status == NTStatus.SUCCESS
    assert response.header.MessageId == 10
    connection.verify_message(response, transport.writes[-1])


async def test_compound_echo_responses_preserve_order_and_ids() -> None:
    connection, transport = make_connection()
    first = make_request(ECHO_REQ(), SMB2Command.ECHO, message_id=31)
    second = make_request(ECHO_REQ(), SMB2Command.ECHO, message_id=32)
    first.header.NextCommand = 72
    first_raw = first.to_bytes() + b"\x00" * (72 - len(first.to_bytes()))

    await connection._handle_smb2_packet(first_raw + second.to_bytes())

    parts = split_compound(transport.writes[-1])
    responses = [SMB2Message.from_bytes(part) for part in parts]
    assert [item.header.MessageId for item in responses] == [31, 32]
    assert [item.header.Status for item in responses] == [
        NTStatus.SUCCESS,
        NTStatus.SUCCESS,
    ]
    assert responses[0].header.NextCommand % 8 == 0
    assert responses[1].header.NextCommand == 0
