"""NetBIOS session-service framing tests without network I/O."""

from typing import Any, List

import pytest

from aiosmb.transport.netbios import NetBIOSPacketizer


pytestmark = pytest.mark.unit


async def _collect(generator: Any) -> List[bytes]:
    return [item async for item in generator]


@pytest.mark.asyncio
async def test_outbound_frame_has_golden_session_header() -> None:
    packetizer = NetBIOSPacketizer()

    frames = await _collect(packetizer.data_out(b"\xfeSMB"))

    assert frames == [b"\x00\x00\x00\x04\xfeSMB"]


@pytest.mark.asyncio
async def test_outbound_none_produces_no_frame() -> None:
    packetizer = NetBIOSPacketizer()

    assert await _collect(packetizer.data_out(None)) == []


@pytest.mark.asyncio
async def test_fragmented_frame_is_emitted_only_when_complete() -> None:
    packetizer = NetBIOSPacketizer()
    payload = b"\xfeSMB deterministic payload"
    wire = b"\x00" + len(payload).to_bytes(3, "big") + payload
    emitted = []

    for octet in wire[:-1]:
        emitted.extend(await _collect(packetizer.data_in(bytes([octet]))))
        assert emitted == []

    emitted.extend(await _collect(packetizer.data_in(wire[-1:])))

    assert emitted == [payload]
    assert packetizer.in_buffer == b""


@pytest.mark.asyncio
async def test_coalesced_frames_and_trailing_partial_frame() -> None:
    packetizer = NetBIOSPacketizer()
    first = b"first"
    second = b"second"
    third = b"third"

    def frame(payload: bytes) -> bytes:
        return b"\x00" + len(payload).to_bytes(3, "big") + payload

    third_wire = frame(third)
    initial = frame(first) + frame(second) + third_wire[:6]

    assert await _collect(packetizer.data_in(initial)) == [first, second]
    assert packetizer.in_buffer == third_wire[:6]
    assert await _collect(packetizer.data_in(third_wire[6:])) == [third]
    assert packetizer.in_buffer == b""


@pytest.mark.asyncio
async def test_truncated_header_is_retained_across_eof_notification() -> None:
    packetizer = NetBIOSPacketizer()

    assert await _collect(packetizer.data_in(b"\x00\x00\x00")) == []
    assert await _collect(packetizer.data_in(None)) == []
    assert packetizer.in_buffer == b"\x00\x00\x00"


@pytest.mark.asyncio
@pytest.mark.xfail(
    strict=True,
    reason="KF-0102: NetBIOS decoder stalls on outbound short frames",
)
async def test_short_outbound_frame_round_trips_through_decoder() -> None:
    encoder = NetBIOSPacketizer()
    decoder = NetBIOSPacketizer()
    payload = b"x"

    wire = (await _collect(encoder.data_out(payload)))[0]
    decoded = await _collect(decoder.data_in(wire))

    assert decoded == [payload]
    assert decoder.in_buffer == b""
