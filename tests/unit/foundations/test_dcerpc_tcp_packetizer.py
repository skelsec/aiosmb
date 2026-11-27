"""Offline tests for DCE/RPC connection-oriented TCP packetization."""

import struct
from typing import Any, List, Optional

import pytest

from aiosmb.dcerpc.v5.transport.tcp import DCERPCPacketizer


pytestmark = pytest.mark.unit


def _response_pdu(
    payload: bytes,
    call_id: int = 1,
    advertised_length: Optional[int] = None,
) -> bytes:
    fragment_length = (
        24 + len(payload) if advertised_length is None else advertised_length
    )
    header = struct.pack(
        "<BBBBIHHIIHBB",
        5,
        0,
        2,
        3,
        0x10,
        fragment_length,
        0,
        call_id,
        len(payload),
        0,
        0,
        0,
    )
    return header + payload


async def _collect(generator: Any) -> List[Optional[bytes]]:
    return [item async for item in generator]


def test_response_fixture_matches_dcerpc_golden_header() -> None:
    assert _response_pdu(b"abc", call_id=7).hex() == (
        "05000203100000001b00000007000000"
        "0300000000000000616263"
    )


@pytest.mark.asyncio
async def test_fragmented_response_is_emitted_only_when_complete() -> None:
    packetizer = DCERPCPacketizer()
    pdu = _response_pdu(b"deterministic payload", call_id=41)
    emitted = []

    for octet in pdu[:-1]:
        emitted.extend(await _collect(packetizer.data_in(bytes([octet]))))
        assert emitted == []

    emitted.extend(await _collect(packetizer.data_in(pdu[-1:])))

    assert emitted == [pdu]
    assert packetizer.in_buffer == b""


@pytest.mark.asyncio
async def test_coalesced_pdus_and_partial_tail_are_packetized_in_order() -> None:
    packetizer = DCERPCPacketizer()
    first = _response_pdu(b"one", call_id=1)
    second = _response_pdu(b"two", call_id=2)
    third = _response_pdu(b"three", call_id=3)

    emitted = await _collect(
        packetizer.data_in(first + second + third[:12])
    )

    assert emitted == [first, second]
    assert packetizer.in_buffer == third[:12]
    assert await _collect(packetizer.data_in(third[12:])) == [third]
    assert packetizer.in_buffer == b""


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "buffer_size,data,expected",
    [
        (4, b"", [b""]),
        (4, b"abcd", [b"abcd"]),
        (4, b"abcde", [b"abcd", b"e"]),
        (4, b"abcdefghij", [b"abcd", b"efgh", b"ij"]),
    ],
)
async def test_outbound_data_respects_write_buffer_boundaries(
    buffer_size: int, data: bytes, expected: List[bytes]
) -> None:
    packetizer = DCERPCPacketizer(buffer_size=buffer_size)

    assert await _collect(packetizer.data_out(data)) == expected


@pytest.mark.asyncio
async def test_incomplete_advertised_fragment_remains_buffered() -> None:
    packetizer = DCERPCPacketizer()
    incomplete = _response_pdu(b"", advertised_length=30)

    assert await _collect(packetizer.data_in(incomplete)) == []
    assert packetizer.in_buffer == incomplete


@pytest.mark.asyncio
@pytest.mark.xfail(
    strict=True,
    reason="KF-0103: DCE/RPC packetizer crashes after yielding EOF",
)
async def test_eof_notification_is_forwarded_without_type_error() -> None:
    packetizer = DCERPCPacketizer()

    assert await _collect(packetizer.data_in(None)) == [None]
    assert packetizer.in_buffer == b""


@pytest.mark.xfail(
    strict=True,
    reason="KF-0104: DCE/RPC packetizer dispatches undersized response fragments",
)
def test_response_fragment_shorter_than_header_is_rejected() -> None:
    packetizer = DCERPCPacketizer()
    packetizer.in_buffer = _response_pdu(b"", advertised_length=23)

    with pytest.raises(ValueError, match="fragment length"):
        list(packetizer.process_buffer())
