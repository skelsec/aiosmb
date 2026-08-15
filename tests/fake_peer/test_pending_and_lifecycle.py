"""Pending-response and receive-loop lifecycle tests."""

import asyncio
import io
from typing import Any, Callable

import pytest

from aiosmb.commons.exceptions import SMBPendingMaxRenewal, SMBPendingTimeout
from aiosmb.connection import SMBConnectionStatus, SMBPendingMsg
from aiosmb.protocol.smb2.commands import CANCEL_REQ, ECHO_REPLY
from aiosmb.protocol.smb2.command_codes import SMB2Command
from aiosmb.protocol.smb2.headers import SMB2Header_SYNC
from aiosmb.protocol.smb2.message import SMB2Message
from aiosmb.wintypes.ntstatus import NTStatus
from tests.support.scripted_smb import ScriptedSMBTransport, connection_reader
from tests.support.smb_connection import make_connection, make_reply


pytestmark = [pytest.mark.fake_peer, pytest.mark.asyncio]
TIMEOUT = 0.5


async def _wait_until(predicate: Callable[[], Any]) -> None:
    async def poll() -> None:
        while not predicate():
            await asyncio.sleep(0)

    await asyncio.wait_for(poll(), timeout=TIMEOUT)


async def _stop_pending(pending: SMBPendingMsg) -> None:
    task = pending.pending_task
    await pending.stop()
    if task is not None:
        try:
            await asyncio.wait_for(task, timeout=TIMEOUT)
        except asyncio.CancelledError:
            pass


async def test_pending_message_run_update_and_stop_are_leak_free() -> None:
    responses = {}
    events = {7: asyncio.Event()}
    pending = SMBPendingMsg(7, responses, events, max_renewal=3)

    await pending.run()
    first_task = pending.pending_task
    await pending.update()
    second_task = pending.pending_task
    await asyncio.sleep(0)

    assert first_task is not second_task
    assert first_task is not None
    assert first_task.cancelled()
    assert pending.max_renewal == 2
    assert not events[7].is_set()

    await _stop_pending(pending)
    assert second_task is not None
    assert second_task.done()


async def test_pending_message_max_renewal_wakes_waiter() -> None:
    responses = {}
    events = {11: asyncio.Event()}
    pending = SMBPendingMsg(11, responses, events, max_renewal=1)

    try:
        await pending.run()
        await pending.update()
        await asyncio.wait_for(events[11].wait(), timeout=TIMEOUT)

        message, error = responses[11]
        assert message is None
        assert isinstance(error, SMBPendingMaxRenewal)
    finally:
        await _stop_pending(pending)


@pytest.mark.xfail(
    strict=True,
    reason="KF-0500: SMBPendingMsg ignores its configured timeout",
)
async def test_pending_message_honors_configured_timeout() -> None:
    responses = {}
    events = {13: asyncio.Event()}
    pending = SMBPendingMsg(13, responses, events, timeout=0.01)

    try:
        await pending.run()
        await asyncio.wait_for(events[13].wait(), timeout=0.1)
        message, error = responses[13]
        assert message is None
        assert isinstance(error, SMBPendingTimeout)
    finally:
        await _stop_pending(pending)


async def test_status_pending_then_final_response_completes_original_waiter() -> None:
    connection = make_connection()
    transport = ScriptedSMBTransport()
    message_id = 19
    connection.OutstandingResponsesEvent[message_id] = asyncio.Event()
    pending_wire = make_reply(
        message_id,
        ECHO_REPLY(),
        status=NTStatus.PENDING,
        async_id=b"pending!",
    ).to_bytes()
    final_wire = make_reply(message_id, ECHO_REPLY()).to_bytes()

    async with connection_reader(connection, transport):
        await transport.feed(pending_wire)
        await _wait_until(lambda: message_id in connection.pending_table)
        pending = connection.pending_table[message_id]

        assert not connection.OutstandingResponsesEvent[message_id].is_set()
        assert pending.pending_task is not None

        await transport.feed(final_wire)
        reply, raw, error = await asyncio.wait_for(
            connection.recvSMB(message_id), timeout=TIMEOUT
        )

        assert error is None
        assert reply.header.Status == NTStatus.SUCCESS
        assert raw == final_wire
        assert message_id not in connection.pending_table
        await _wait_until(lambda: pending.pending_task.done())


@pytest.mark.xfail(
    strict=True,
    reason="KF-0501: repeated STATUS_PENDING replaces rather than renews state",
)
async def test_repeated_pending_response_renews_existing_lifecycle() -> None:
    connection = make_connection()
    connection.target.PendingMaxRenewal = 3
    transport = ScriptedSMBTransport()
    message_id = 23
    connection.OutstandingResponsesEvent[message_id] = asyncio.Event()
    pending_wire = make_reply(
        message_id,
        ECHO_REPLY(),
        status=NTStatus.PENDING,
        async_id=b"pending!",
    ).to_bytes()
    first = None

    try:
        async with connection_reader(connection, transport):
            await transport.feed(pending_wire)
            await _wait_until(lambda: message_id in connection.pending_table)
            first = connection.pending_table[message_id]

            await transport.feed(pending_wire)
            await _wait_until(lambda: connection.pending_table[message_id] is not first)

            assert connection.pending_table[message_id] is first
            assert first.max_renewal == 2
    finally:
        pending_messages = [first, connection.pending_table.get(message_id)]
        for pending in pending_messages:
            if pending is not None:
                await _stop_pending(pending)


async def test_transport_eof_releases_all_outstanding_receivers() -> None:
    connection = make_connection(status=SMBConnectionStatus.NEGOTIATING)
    transport = ScriptedSMBTransport()
    message_ids = (31, 32)
    for message_id in message_ids:
        connection.OutstandingResponsesEvent[message_id] = asyncio.Event()

    async with connection_reader(connection, transport) as reader:
        await transport.feed_eof()
        await asyncio.wait_for(
            asyncio.gather(
                *[
                    connection.OutstandingResponsesEvent[message_id].wait()
                    for message_id in message_ids
                ]
            ),
            timeout=TIMEOUT,
        )
        await asyncio.wait_for(reader, timeout=TIMEOUT)

        assert connection.connection_closed_evt.is_set()
        for message_id in message_ids:
            message, raw, error = await connection.recvSMB(message_id)
            assert message is None
            assert raw is None
            assert isinstance(error, Exception)
            assert str(error) == "Connection closed"


@pytest.mark.xfail(
    strict=True,
    reason="KF-0505: receive-loop EOF leaves a running connection state open",
)
async def test_transport_eof_transitions_running_connection_to_closed() -> None:
    connection = make_connection()
    transport = ScriptedSMBTransport()

    async with connection_reader(connection, transport) as reader:
        await transport.feed_eof()
        await asyncio.wait_for(reader, timeout=0.1)
        assert connection.status == SMBConnectionStatus.CLOSED


async def test_cancelled_receiver_does_not_consume_later_response() -> None:
    connection = make_connection()
    message_id = 37
    connection.OutstandingResponsesEvent[message_id] = asyncio.Event()
    receiver = asyncio.create_task(connection.recvSMB(message_id))
    await asyncio.sleep(0)

    receiver.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(receiver, timeout=TIMEOUT)

    reply = make_reply(message_id, ECHO_REPLY())
    raw = reply.to_bytes()
    connection.OutstandingResponses[message_id] = (reply, raw)
    connection.OutstandingResponsesEvent[message_id].set()

    received, received_raw, error = await asyncio.wait_for(
        connection.recvSMB(message_id), timeout=TIMEOUT
    )
    assert error is None
    assert received is reply
    assert received_raw == raw


async def test_cancel_wire_reuses_message_id_without_consuming_credit() -> None:
    connection = make_connection()
    connection.SequenceWindow = 50
    transport = ScriptedSMBTransport()
    connection.network_connection = transport
    header = SMB2Header_SYNC()
    header.Command = SMB2Command.CANCEL
    header.MessageId = 17
    message = SMB2Message(header, CANCEL_REQ())

    message_id, error = await asyncio.wait_for(
        connection.sendSMB(message), timeout=TIMEOUT
    )

    assert error is None
    assert message_id == 17
    assert connection.SequenceWindow == 50
    wire_header = SMB2Header_SYNC.from_buffer(io.BytesIO(transport.writes[0]))
    assert wire_header.MessageId == 17
    assert wire_header.Command == SMB2Command.CANCEL
    await transport.close()


@pytest.mark.xfail(
    strict=True,
    reason="KF-0502: SMB2 CANCEL waits for a response forbidden by the protocol",
)
async def test_cancel_completes_after_sending_without_peer_response() -> None:
    connection = make_connection()
    transport = ScriptedSMBTransport()

    async with connection_reader(connection, transport):
        result, error = await asyncio.wait_for(
            connection.cancel(41), timeout=0.1
        )
        assert result is True
        assert error is None
