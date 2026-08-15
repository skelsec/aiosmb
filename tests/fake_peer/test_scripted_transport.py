"""Behavioral contract for the reusable scripted transport."""

import asyncio

import pytest

from tests.support.scripted_smb import ScriptedSMBTransport


pytestmark = [pytest.mark.fake_peer, pytest.mark.asyncio]
TIMEOUT = 0.5


async def test_transport_records_write_and_replays_ordered_script() -> None:
    async def respond(
        wire_data: bytes, transport: ScriptedSMBTransport
    ):
        await asyncio.sleep(0)
        return [b"first", wire_data[::-1]]

    transport = ScriptedSMBTransport([respond])
    reader = transport.read()
    write_waiter = asyncio.create_task(transport.wait_for_writes(1, TIMEOUT))

    await asyncio.wait_for(transport.write(b"request"), timeout=TIMEOUT)
    assert await asyncio.wait_for(write_waiter, timeout=TIMEOUT) == [b"request"]
    assert await asyncio.wait_for(reader.__anext__(), timeout=TIMEOUT) == b"first"
    assert await asyncio.wait_for(reader.__anext__(), timeout=TIMEOUT) == b"tseuqer"

    await asyncio.wait_for(transport.close(), timeout=TIMEOUT)
    with pytest.raises(StopAsyncIteration):
        await asyncio.wait_for(reader.__anext__(), timeout=TIMEOUT)
    assert transport.closed is True
    assert transport.remaining_actions == 0


async def test_transport_surfaces_scripted_read_error() -> None:
    transport = ScriptedSMBTransport([ValueError("scripted peer failure")])
    reader = transport.read()

    await asyncio.wait_for(transport.write(b"request"), timeout=TIMEOUT)
    with pytest.raises(ValueError, match="scripted peer failure"):
        await asyncio.wait_for(reader.__anext__(), timeout=TIMEOUT)
    await asyncio.wait_for(transport.close(), timeout=TIMEOUT)
