"""Golden vectors for primitive Windows wire types."""

import datetime
import io

import pytest

from aiosmb.wintypes.dtyp.constrcuted_security.guid import GUID
from aiosmb.wintypes.dtyp.constrcuted_security.sid import SID, well_known_sids
from aiosmb.wintypes.dtyp.structures.filetime import FILETIME


pytestmark = pytest.mark.unit


def _filetime_bytes(value):
    return value.to_bytes(8, "little")


def test_sid_parses_golden_vector_and_consumes_exact_length():
    raw = bytes.fromhex(
        "0103000000000005"
        "15000000"
        "2a000000"
        "ffffffff"
    )
    buff = io.BytesIO(raw + b"tail")

    sid = SID.from_buffer(buff)

    assert sid.Revision == 1
    assert sid.SubAuthorityCount == 3
    assert sid.IdentifierAuthority == 5
    assert sid.SubAuthority == [21, 42, 0xFFFFFFFF]
    assert str(sid) == "S-1-5-21-42-4294967295"
    assert buff.read() == b"tail"


def test_sid_round_trip_when_subauthorities_fill_wire_words():
    text = "S-1-5-16909060-2864434397"
    expected = bytes.fromhex(
        "0102000000000005"
        "04030201"
        "ddccbbaa"
    )

    encoded = SID.from_string(text).to_bytes()
    decoded = SID.from_bytes(encoded)

    assert encoded == expected
    assert str(decoded) == text


def test_sid_supports_hex_identifier_authority_and_wildcards():
    high_authority = SID.from_string("S-1-0x010203040506")
    wildcard = SID.from_string("S-1-5-x-y", wildcard=True)

    assert high_authority.IdentifierAuthority == 0x010203040506
    assert str(high_authority) == "S-1-0x010203040506"
    assert wildcard.SubAuthority == ["x", "y"]
    assert wildcard.wildcard is True
    assert str(wildcard) == "S-1-5-x-y"
    assert str(well_known_sids["EVERYONE"]) == "S-1-1-0"


@pytest.mark.parametrize(
    "text,exception",
    [
        ("not-a-sid", Exception),
        ("S-1-5-not-a-number", ValueError),
    ],
)
def test_sid_rejects_malformed_strings(text, exception):
    with pytest.raises(exception):
        SID.from_string(text)


@pytest.mark.xfail(
    strict=True,
    reason="KF-0300: SID encoder emits variable-width subauthorities",
)
def test_sid_encoder_uses_four_bytes_per_subauthority():
    sid = SID.from_string("S-1-5-21-0-42")
    expected = bytes.fromhex(
        "0103000000000005"
        "15000000"
        "00000000"
        "2a000000"
    )

    assert sid.to_bytes() == expected


@pytest.mark.xfail(
    strict=True,
    reason="KF-0304: SID parser accepts truncated wire data",
)
def test_sid_rejects_truncated_subauthority():
    truncated = bytes.fromhex("010200000000000515000000")

    with pytest.raises(Exception):
        SID.from_bytes(truncated)


def test_guid_parses_windows_mixed_endian_golden_vector():
    wire = bytes.fromhex("33221100554477668899aabbccddeeff")
    buff = io.BytesIO(wire + b"tail")

    guid = GUID.from_buffer(buff)

    assert guid.Data1 == bytes.fromhex("00112233")
    assert guid.Data2 == bytes.fromhex("4455")
    assert guid.Data3 == bytes.fromhex("6677")
    assert guid.Data4 == bytes.fromhex("8899aabbccddeeff")
    assert str(guid) == "00112233-4455-6677-8899-aabbccddeeff"
    assert buff.read() == b"tail"


def test_guid_string_round_trip_preserves_canonical_fields():
    text = "00112233-4455-6677-8899-aabbccddeeff"

    original = GUID.from_string(text)
    reparsed = GUID.from_string(str(original))

    assert str(reparsed) == text
    assert reparsed.Data1 == original.Data1
    assert reparsed.Data2 == original.Data2
    assert reparsed.Data3 == original.Data3
    assert reparsed.Data4 == original.Data4


@pytest.mark.parametrize("text", ["not-a-guid", "00112233-4455-6677-8899-zz"])
def test_guid_rejects_malformed_strings(text):
    with pytest.raises((IndexError, ValueError)):
        GUID.from_string(text)


@pytest.mark.xfail(
    strict=True,
    reason="KF-0301: GUID encoder omits Windows mixed-endian conversion",
)
def test_guid_string_serializes_to_windows_wire_order():
    guid = GUID.from_string("00112233-4455-6677-8899-aabbccddeeff")

    assert guid.to_bytes() == bytes.fromhex(
        "33221100554477668899aabbccddeeff"
    )


@pytest.mark.xfail(
    strict=True,
    reason="KF-0305: GUID parser accepts truncated wire data",
)
def test_guid_rejects_truncated_wire_data():
    with pytest.raises(Exception):
        GUID.from_bytes(b"\x00" * 15)


@pytest.mark.parametrize(
    "raw,expected",
    [
        (0, datetime.datetime(1970, 1, 1)),
        (116444736000000000, datetime.datetime(1970, 1, 1)),
        (132223104000000000, datetime.datetime(2020, 1, 1)),
        (0xFFFFFFFFFFFFFFFF, datetime.datetime(3000, 1, 1)),
    ],
)
def test_filetime_golden_values(raw, expected):
    parsed = FILETIME.from_bytes(_filetime_bytes(raw))

    assert parsed.dwLowDateTime == raw & 0xFFFFFFFF
    assert parsed.dwHighDateTime == raw >> 32
    assert parsed.datetime == expected


def test_filetime_from_dict_matches_wire_parser():
    raw = 132223104000000000
    from_dict = FILETIME.from_dict(
        {
            "dwLowDateTime": raw & 0xFFFFFFFF,
            "dwHighDateTime": raw >> 32,
        }
    )

    assert from_dict.datetime == FILETIME.from_bytes(_filetime_bytes(raw)).datetime


def test_filetime_from_dict_requires_both_words():
    with pytest.raises(KeyError):
        FILETIME.from_dict({"dwLowDateTime": 0})


@pytest.mark.xfail(
    strict=True,
    reason="KF-0306: FILETIME parser accepts truncated wire data",
)
def test_filetime_rejects_truncated_wire_data():
    with pytest.raises(Exception):
        FILETIME.from_bytes(b"\x00" * 7)
