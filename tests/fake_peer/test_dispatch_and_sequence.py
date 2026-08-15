"""Scripted send/receive correlation and dispatch tests."""

import asyncio
import zlib

import pytest

from aiosmb.connection import SMBConnectionStatus
from aiosmb.protocol.common import NegotiateDialects
from aiosmb.protocol.compression import backend as compression_backend
from aiosmb.protocol.smb2.command_codes import SMB2Command
from aiosmb.protocol.smb2.commands import (
    ECHO_REPLY,
    ECHO_REQ,
    ERROR_REPLY,
    SESSION_SETUP_REPLY,
)
from aiosmb.protocol.smb2.commands.negotiate import (
    SMB2Cipher,
    SMB2CompressionType,
)
from aiosmb.protocol.smb2.commands.sessionsetup import SessionFlags
from aiosmb.protocol.smb2.headers import SMB2HeaderFlag
from aiosmb.protocol.smb2.message import SMB2Message
from aiosmb.wintypes.ntstatus import NTStatus
from tests.support.scripted_smb import ScriptedSMBTransport, connection_reader
from tests.support.smb_connection import make_connection, make_reply, make_request


pytestmark = [pytest.mark.fake_peer, pytest.mark.asyncio]
TIMEOUT = 0.5


def _echo_reply_for_write(wire_data: bytes, transport: ScriptedSMBTransport) -> bytes:
    request = SMB2Message.from_bytes(wire_data)
    return make_reply(request.header.MessageId, ECHO_REPLY()).to_bytes()


async def test_scripted_transport_drives_high_level_echo_round_trip() -> None:
    connection = make_connection()
    transport = ScriptedSMBTransport([_echo_reply_for_write])

    async with connection_reader(connection, transport):
        result, error = await asyncio.wait_for(connection.echo(), timeout=TIMEOUT)

        assert result is True
        assert error is None
        assert transport.remaining_actions == 0
        request = SMB2Message.from_bytes(transport.writes[0])
        assert request.header.MessageId == 0
        assert request.header.SessionId == connection.SessionId


async def test_out_of_order_responses_correlate_by_message_id() -> None:
    connection = make_connection()
    connection.SessionId = 0x11223344
    transport = ScriptedSMBTransport()

    async with connection_reader(connection, transport):
        first_id, first_error = await connection.sendSMB(make_request(ECHO_REQ()))
        second_id, second_error = await connection.sendSMB(make_request(ECHO_REQ()))
        assert first_error is None
        assert second_error is None
        assert (first_id, second_id) == (0, 1)

        second_wire = make_reply(second_id, ECHO_REPLY()).to_bytes()
        first_wire = make_reply(first_id, ECHO_REPLY()).to_bytes()
        await transport.feed(second_wire)
        await transport.feed(first_wire)

        first, first_raw, error = await asyncio.wait_for(
            connection.recvSMB(first_id), timeout=TIMEOUT
        )
        assert error is None
        second, second_raw, error = await asyncio.wait_for(
            connection.recvSMB(second_id), timeout=TIMEOUT
        )
        assert error is None
        assert first.header.MessageId == first_id
        assert second.header.MessageId == second_id
        assert first_raw == first_wire
        assert second_raw == second_wire
        assert connection.OutstandingResponsesEvent == {}


async def test_send_sequence_window_advances_by_full_credit_charge() -> None:
    connection = make_connection()
    transport = ScriptedSMBTransport()
    connection.network_connection = transport

    first_id, first_error = await asyncio.wait_for(
        connection.sendSMB(make_request(ECHO_REQ(), credit_charge=3)),
        timeout=TIMEOUT,
    )
    second_id, second_error = await asyncio.wait_for(
        connection.sendSMB(make_request(ECHO_REQ(), credit_charge=2)),
        timeout=TIMEOUT,
    )

    assert first_error is None
    assert second_error is None
    assert (first_id, second_id) == (0, 3)
    assert connection.SequenceWindow == 5
    first = SMB2Message.from_bytes(transport.writes[0])
    second = SMB2Message.from_bytes(transport.writes[1])
    assert (first.header.CreditCharge, second.header.CreditCharge) == (3, 2)
    assert (first.header.CreditReq, second.header.CreditReq) == (127, 127)
    await transport.close()


async def test_send_lock_serializes_concurrent_multicredit_requests() -> None:
    first_write_started = asyncio.Event()
    release_first_write = asyncio.Event()

    async def block_first_write(
        wire_data: bytes, transport: ScriptedSMBTransport
    ) -> None:
        first_write_started.set()
        await asyncio.wait_for(release_first_write.wait(), timeout=TIMEOUT)

    connection = make_connection()
    transport = ScriptedSMBTransport([block_first_write, None])
    connection.network_connection = transport
    first_task = asyncio.create_task(
        connection.sendSMB(make_request(ECHO_REQ(), credit_charge=4))
    )
    await asyncio.wait_for(first_write_started.wait(), timeout=TIMEOUT)
    second_task = asyncio.create_task(
        connection.sendSMB(make_request(ECHO_REQ(), credit_charge=2))
    )
    await asyncio.sleep(0)

    assert len(transport.writes) == 1
    release_first_write.set()
    first_result, second_result = await asyncio.wait_for(
        asyncio.gather(first_task, second_task), timeout=TIMEOUT
    )

    assert first_result == (0, None)
    assert second_result == (4, None)
    assert connection.SequenceWindow == 6
    assert [
        SMB2Message.from_bytes(wire).header.MessageId for wire in transport.writes
    ] == [0, 4]
    await transport.close()


async def test_recv_guard_rejects_wait_while_current_task_holds_send_lock() -> None:
    observed = []
    connection = make_connection()

    async def receive_during_write(
        wire_data: bytes, transport: ScriptedSMBTransport
    ) -> None:
        request = SMB2Message.from_bytes(wire_data)
        observed.append(await connection.recvSMB(request.header.MessageId))

    transport = ScriptedSMBTransport([receive_during_write])
    connection.network_connection = transport
    message_id, error = await asyncio.wait_for(
        connection.sendSMB(make_request(ECHO_REQ())), timeout=TIMEOUT
    )

    assert error is None
    assert message_id == 0
    assert len(observed) == 1
    message, raw, receive_error = observed[0]
    assert message is None
    assert raw is None
    assert isinstance(receive_error, RuntimeError)
    assert "holds send_lock" in str(receive_error)
    assert connection._send_lock_owner is None
    await transport.close()


@pytest.mark.xfail(
    strict=True,
    reason="KF-0504: cancelling a lock waiter clears the active send-lock owner",
)
async def test_cancelled_send_waiter_does_not_clear_active_lock_owner() -> None:
    first_write_started = asyncio.Event()
    release_first_write = asyncio.Event()

    async def block_first_write(
        wire_data: bytes, transport: ScriptedSMBTransport
    ) -> None:
        first_write_started.set()
        await asyncio.wait_for(release_first_write.wait(), timeout=TIMEOUT)

    connection = make_connection()
    transport = ScriptedSMBTransport([block_first_write])
    connection.network_connection = transport
    owner = asyncio.create_task(connection.sendSMB(make_request(ECHO_REQ())))
    await asyncio.wait_for(first_write_started.wait(), timeout=TIMEOUT)
    waiter = asyncio.create_task(connection.sendSMB(make_request(ECHO_REQ())))
    await asyncio.sleep(0)

    waiter.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(waiter, timeout=TIMEOUT)

    try:
        assert connection._send_lock_owner is owner
    finally:
        release_first_write.set()
        await asyncio.wait_for(owner, timeout=TIMEOUT)
        await transport.close()


async def test_plain_error_packet_is_dispatched_to_waiter() -> None:
    connection = make_connection()
    transport = ScriptedSMBTransport()
    message_id = 61
    connection.OutstandingResponsesEvent[message_id] = asyncio.Event()
    error_body = ERROR_REPLY()
    wire = make_reply(
        message_id,
        error_body,
        status=NTStatus.ACCESS_DENIED,
    ).to_bytes()

    async with connection_reader(connection, transport):
        await transport.feed(wire)
        reply, raw, error = await asyncio.wait_for(
            connection.recvSMB(message_id), timeout=TIMEOUT
        )

        assert error is None
        assert reply.header.Status == NTStatus.ACCESS_DENIED
        assert isinstance(reply.command, ERROR_REPLY)
        assert raw == wire


async def test_signed_session_setup_is_deferred_until_key_derivation() -> None:
    connection = make_connection(
        status=SMBConnectionStatus.SESSIONSETUP,
        dialect=NegotiateDialects.SMB311,
    )
    transport = ScriptedSMBTransport()
    message_id = 41
    body = SESSION_SETUP_REPLY()
    body.SessionFlags = SessionFlags(0)
    body.Buffer = b""
    reply = make_reply(
        message_id,
        body,
        command=SMB2Command.SESSION_SETUP,
    )
    reply.header.Flags |= SMB2HeaderFlag.SMB2_FLAGS_SIGNED
    reply.header.Signature = b"\xa5" * 16
    connection.OutstandingResponsesEvent[message_id] = asyncio.Event()

    async with connection_reader(connection, transport):
        await transport.feed(reply.to_bytes())
        await asyncio.wait_for(
            connection.OutstandingResponsesEvent[message_id].wait(),
            timeout=TIMEOUT,
        )
        observed, _, error = await connection.recvSMB(message_id)

    assert error is None
    assert observed.header.Command is SMB2Command.SESSION_SETUP


async def test_compressed_packet_is_expanded_before_dispatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = make_connection(
        dialect=NegotiateDialects.SMB311,
    )
    connection.CompressionIds = [SMB2CompressionType.LZ77]
    connection.CompressionId = SMB2CompressionType.LZ77
    connection.compression_min_size = 1
    monkeypatch.setattr(
        compression_backend,
        "compress",
        lambda algorithm, data: zlib.compress(data),
    )
    monkeypatch.setattr(
        compression_backend,
        "decompress",
        lambda algorithm, data, expected_size, max_output_size: zlib.decompress(
            data
        ),
    )
    transport = ScriptedSMBTransport()
    message_id = 67
    connection.OutstandingResponsesEvent[message_id] = asyncio.Event()
    plain = make_reply(message_id, ECHO_REPLY()).to_bytes()
    compressed = (
        await connection.compress_message(make_reply(message_id, ECHO_REPLY()))
    ).to_bytes()

    async with connection_reader(connection, transport):
        await transport.feed(compressed)
        reply, raw, error = await asyncio.wait_for(
            connection.recvSMB(message_id), timeout=TIMEOUT
        )

        assert error is None
        assert reply.header.MessageId == message_id
        assert isinstance(reply.command, ECHO_REPLY)
        assert raw == plain


async def test_encrypted_packet_uses_transform_integrity_without_inner_signature(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = bytes(range(16))
    nonce = b"\x42" * 11
    connection = make_connection(dialect=NegotiateDialects.SMB311)
    connection.CipherId = SMB2Cipher.AES_128_CCM
    connection.DecryptionKey = key
    connection.SigningKey = b"\x99" * 16
    connection.SessionId = 0x88776655
    peer = make_connection(dialect=NegotiateDialects.SMB311)
    peer.CipherId = SMB2Cipher.AES_128_CCM
    peer.EncryptionKey = key
    peer.SessionId = connection.SessionId
    monkeypatch.setattr("aiosmb.connection.os.urandom", lambda size: nonce)
    transport = ScriptedSMBTransport()
    message_id = 71
    connection.OutstandingResponsesEvent[message_id] = asyncio.Event()
    inner_reply = make_reply(
        message_id,
        ECHO_REPLY(),
        session_id=connection.SessionId,
    )
    inner_reply.header.Flags |= SMB2HeaderFlag.SMB2_FLAGS_SIGNED
    inner_reply.header.Signature = b"\xa5" * 16
    plain = inner_reply.to_bytes()
    encrypted = peer.encrypt_message(plain).to_bytes()

    async with connection_reader(connection, transport):
        await transport.feed(encrypted)
        reply, raw, error = await asyncio.wait_for(
            connection.recvSMB(message_id), timeout=TIMEOUT
        )

        assert error is None
        assert reply.header.MessageId == message_id
        assert isinstance(reply.command, ECHO_REPLY)
        assert raw == plain
