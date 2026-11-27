"""Golden, boundary, malformed-input, and generative LZNT1 tests."""

import struct
from typing import List

import pytest

from aiosmb.protocol.compression.lznt1 import compress, decompress


pytestmark = pytest.mark.unit


def _declared_chunk_lengths(encoded: bytes) -> List[int]:
    lengths = []
    remaining = encoded
    while remaining:
        assert len(remaining) >= 2
        header = int.from_bytes(remaining[:2], "little")
        length = (header & 0x0FFF) + 1
        assert len(remaining[2:]) >= length
        lengths.append(length)
        remaining = remaining[2 + length :]
    return lengths


@pytest.mark.parametrize(
    "encoded,expected",
    [
        (bytes.fromhex("033041424344"), b"ABCD"),
        (bytes.fromhex("05b0084142430320"), b"ABCABCABC"),
    ],
)
def test_decompresses_independent_golden_vectors(
    encoded: bytes, expected: bytes
) -> None:
    assert bytes(decompress(encoded)) == expected


@pytest.mark.parametrize(
    "plain,expected",
    [
        (b"", b""),
        (b"ABCD", bytes.fromhex("033041424344")),
        (b"ABCABCABC", bytes.fromhex("05b0084142430320")),
    ],
)
def test_compression_is_deterministic_for_golden_vectors(
    plain: bytes, expected: bytes
) -> None:
    assert compress(plain) == expected


@pytest.mark.parametrize(
    "plain",
    [
        b"",
        b"\x00",
        bytes(range(64)),
        b"A" * 4095,
        b"A" * 4096,
        b"A" * 4097,
        bytes(range(251)) * 20,
    ],
    ids=[
        "empty",
        "one-byte",
        "literal-data",
        "chunk-minus-one",
        "exact-chunk",
        "chunk-plus-one",
        "multi-chunk-pattern",
    ],
)
def test_compress_decompress_round_trip_at_chunk_boundaries(plain: bytes) -> None:
    encoded = compress(plain)

    assert bytes(decompress(encoded)) == plain
    assert all(length <= 0x1000 for length in _declared_chunk_lengths(encoded))


def test_default_chunk_boundary_creates_two_independent_chunks() -> None:
    plain = b"A" * 4097

    encoded = compress(plain)

    assert len(_declared_chunk_lengths(encoded)) == 2
    assert bytes(decompress(encoded)) == plain


def test_truncated_chunk_is_rejected_by_default() -> None:
    with pytest.raises(ValueError, match="invalid chunk length"):
        decompress(bytes.fromhex("03304142"))


def test_length_check_can_explicitly_recover_available_literal_bytes() -> None:
    assert bytes(decompress(bytes.fromhex("03304142"), length_check=False)) == b"AB"


def test_incomplete_header_is_rejected() -> None:
    with pytest.raises(struct.error):
        decompress(b"\x00")


def test_back_reference_before_output_is_rejected() -> None:
    malformed = bytes.fromhex("02b0010000")

    with pytest.raises((ValueError, IndexError, ZeroDivisionError, struct.error)):
        decompress(malformed)


try:
    from hypothesis import given, settings
    from hypothesis import strategies as st
except ImportError:
    given = None


if given is not None:

    @given(
        plain=st.binary(min_size=0, max_size=128),
        chunk_size=st.sampled_from([16, 31, 64, 128, 0x1000]),
    )
    @settings(max_examples=40, deadline=None, derandomize=True)
    def test_hypothesis_round_trip_for_bounded_binary_data(
        plain: bytes, chunk_size: int
    ) -> None:
        assert bytes(decompress(compress(plain, chunk_size=chunk_size))) == plain

else:

    @pytest.mark.skip(reason="Hypothesis is not installed in the test environment")
    def test_hypothesis_round_trip_for_bounded_binary_data() -> None:
        pass
