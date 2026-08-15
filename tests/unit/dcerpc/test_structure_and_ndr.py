"""Representative legacy Structure, NDR32, and NDR64 wire contracts."""

import io
import struct

import pytest

from aiosmb.dcerpc.v5.enum import Enum
from aiosmb.dcerpc.v5.ndr import (
    NDRBOOLEAN,
    NDRCALL,
    NDRDOUBLEFLOAT,
    NDRENUM,
    NDRFLOAT,
    NDRHYPER,
    NDRLONG,
    NDRPOINTER,
    NDRPOINTERNULL,
    NDRSHORT,
    NDRSTRUCT,
    NDRUHYPER,
    NDRULONG,
    NDRUNION,
    NDRUniConformantArray,
    NDRUniVaryingArray,
    NDRUSHORT,
    NDRUSMALL,
)
from aiosmb.dcerpc.v5.structure import Structure
from aiosmb.dcerpc.v5.uuid import uuidtup_to_bin


pytestmark = pytest.mark.unit


class _LegacyPacket(Structure):
    structure = (
        ("Magic", "'DC"),
        ("PayloadLength", "<H-Payload"),
        ("Payload", ":"),
        ("Name", "z"),
    )


class _CountedWords(Structure):
    structure = (("Values", "<B*<H"),)


class _AlignedLegacy(Structure):
    alignment = 4
    structure = (
        ("Tag", "<B"),
        ("Value", "<L"),
    )


class _InnerLegacy(Structure):
    structure = (("Value", "<L=0"),)


class _OuterLegacy(Structure):
    structure = (("Inner", ":", _InnerLegacy),)


class _Pair(NDRSTRUCT):
    structure = (
        ("Small", NDRUSMALL),
        ("Long", NDRULONG),
    )


class _Color(NDRENUM):
    class enumItems(Enum):
        RED = 1
        BLUE = 2


class _ByteVaryingArray(NDRUniVaryingArray):
    item = "B"


class _ByteConformantArray(NDRUniConformantArray):
    item = "B"


class _ArrayCall(NDRCALL):
    structure = (
        ("Marker", NDRULONG),
        ("Payload", _ByteConformantArray),
    )


class _Choice(NDRUNION):
    union = {
        1: ("Long", NDRULONG),
        2: ("Short", NDRUSHORT),
    }


class _PLong(NDRPOINTER):
    referent = (("Data", NDRULONG),)


class _TrailingGap(NDRSTRUCT):
    structure = (
        ("Long", NDRLONG),
        ("Short", NDRUSHORT),
    )


def test_structure_literal_length_ascii_and_raw_payload_round_trip():
    packet = _LegacyPacket()
    packet["Payload"] = b"\x10\x20\x30"
    packet["Name"] = "node"

    wire = packet.getData()

    assert wire == b"DC\x03\x00\x10\x20\x30node\x00"
    assert len(packet) == len(wire)
    assert packet.packField("PayloadLength") == b"\x03\x00"

    parsed = _LegacyPacket(wire)
    assert parsed["Magic"] == "DC"
    assert parsed["PayloadLength"] == 3
    assert parsed["Payload"] == b"\x10\x20\x30"
    assert parsed["Name"] == "node"
    assert parsed.getData() == wire


def test_structure_counted_array_round_trip():
    values = _CountedWords()
    values["Values"] = [0x1122, 0x3344, 0x5566]

    wire = values.getData()

    assert wire == bytes.fromhex("03221144336655")
    assert _CountedWords(wire)["Values"] == [0x1122, 0x3344, 0x5566]


def test_structure_alignment_applies_between_fields():
    value = _AlignedLegacy()
    value["Tag"] = 0x7F
    value["Value"] = 0x11223344

    wire = value.getData()

    assert wire == bytes.fromhex("7f00000044332211")
    parsed = _AlignedLegacy(wire)
    assert parsed["Tag"] == 0x7F
    assert parsed["Value"] == 0x11223344


def test_structure_nested_literal_and_from_file_contracts():
    inner = _InnerLegacy()
    inner["Value"] = 0xAABBCCDD
    outer = _OuterLegacy()
    outer["Inner"] = inner

    assert outer.getData() == bytes.fromhex("ddccbbaa")
    parsed = _OuterLegacy(outer.getData())
    assert isinstance(parsed["Inner"], _InnerLegacy)
    assert parsed["Inner"]["Value"] == 0xAABBCCDD
    from_file = _InnerLegacy.fromFile(io.BytesIO(inner.getData()))
    assert from_file["Value"] == 0xAABBCCDD


def test_structure_rejects_wrong_literal_and_unterminated_ascii():
    with pytest.raises(Exception, match="doesn't match constant value"):
        _LegacyPacket(b"XX\x00\x00name\x00")

    packet = _LegacyPacket()
    with pytest.raises(Exception, match="not NUL terminated"):
        packet.unpack("z", b"name", field="Name")


@pytest.mark.parametrize(
    "ndr_type, value, wire",
    [
        (NDRSHORT, -2, "feff"),
        (NDRUSHORT, 0xBEEF, "efbe"),
        (NDRLONG, -2, "feffffff"),
        (NDRULONG, 0x89ABCDEF, "efcdab89"),
        (NDRHYPER, -2, "feffffffffffffff"),
        (NDRUHYPER, 0x0123456789ABCDEF, "efcdab8967452301"),
    ],
)
def test_ndr_integer_primitive_contracts(ndr_type, value, wire):
    original = ndr_type()
    original["Data"] = value

    assert original.getData() == bytes.fromhex(wire)
    assert ndr_type(bytes.fromhex(wire))["Data"] == value


@pytest.mark.parametrize("is_ndr64", [False, True])
def test_ndr_float_boolean_and_double_contracts(is_ndr64):
    single = NDRFLOAT(isNDR64=is_ndr64)
    single["Data"] = 1.5
    double = NDRDOUBLEFLOAT(isNDR64=is_ndr64)
    double["Data"] = -2.25
    boolean = NDRBOOLEAN(isNDR64=is_ndr64)
    boolean["Data"] = 1

    assert single.getData() == struct.pack("<f", 1.5)
    assert double.getData() == struct.pack("<d", -2.25)
    assert boolean.getData() == b"\x01"
    assert NDRFLOAT(single.getData(), isNDR64=is_ndr64)["Data"] == 1.5
    assert (
        NDRDOUBLEFLOAT(double.getData(), isNDR64=is_ndr64)["Data"] == -2.25
    )


@pytest.mark.parametrize("is_ndr64", [False, True])
def test_ndr_structure_alignment_and_round_trip(is_ndr64):
    pair = _Pair(isNDR64=is_ndr64)
    pair["Small"] = 1
    pair["Long"] = 0x11223344

    wire = pair.getData()

    assert wire == bytes.fromhex("01bfbfbf44332211")
    assert pair.getAlignment() == 4
    parsed = _Pair(wire, isNDR64=is_ndr64)
    assert parsed["Small"] == 1
    assert parsed["Long"] == 0x11223344


@pytest.mark.parametrize(
    "is_ndr64, wire",
    [
        (False, "0200"),
        (True, "02000000"),
    ],
)
def test_ndr_enum_width_changes_for_ndr64(is_ndr64, wire):
    color = _Color(isNDR64=is_ndr64)
    color["Data"] = _Color.enumItems.BLUE

    assert color.getData() == bytes.fromhex(wire)
    assert _Color(bytes.fromhex(wire), isNDR64=is_ndr64)["Data"] == 2


def test_change_transfer_syntax_promotes_enum_to_ndr64():
    color = _Color()
    color["Data"] = 2
    assert color.getData() == bytes.fromhex("0200")

    color.changeTransferSyntax(
        uuidtup_to_bin(("71710533-BEBA-4937-8319-B5DBEF9CCC36", "1.0"))
    )

    assert color._isNDR64 is True
    assert color.getAlignment() == 4
    assert color.getData() == bytes.fromhex("02000000")


@pytest.mark.parametrize(
    "is_ndr64, wire",
    [
        (False, "0000000003000000112233"),
        (True, "00000000000000000300000000000000112233"),
    ],
)
def test_ndr_varying_array_count_width_and_round_trip(is_ndr64, wire):
    array = _ByteVaryingArray(isNDR64=is_ndr64)
    array["Data"] = [0x11, 0x22, 0x33]

    assert array.getData() == bytes.fromhex(wire)
    parsed = _ByteVaryingArray(bytes.fromhex(wire), isNDR64=is_ndr64)
    assert parsed["Offset"] == 0
    assert parsed["ActualCount"] == 3
    assert parsed["Data"] == [0x11, 0x22, 0x33]


@pytest.mark.parametrize(
    "is_ndr64, wire",
    [
        (False, "4433221103000000010203"),
        (True, "44332211cececece0300000000000000010203"),
    ],
)
def test_ndr_call_conformant_count_width_and_round_trip(is_ndr64, wire):
    call = _ArrayCall(isNDR64=is_ndr64)
    call["Marker"] = 0x11223344
    call["Payload"] = [1, 2, 3]

    assert call.getData() == bytes.fromhex(wire)
    parsed = _ArrayCall(bytes.fromhex(wire), isNDR64=is_ndr64)
    assert parsed["Marker"] == 0x11223344
    assert parsed["Payload"] == [1, 2, 3]


@pytest.mark.parametrize(
    "is_ndr64, pointer_wire",
    [
        (False, "44332211"),
        (True, "4433221100000000"),
    ],
)
def test_ndr_pointer_header_and_referent_are_separate(is_ndr64, pointer_wire):
    pointer = _PLong(isNDR64=is_ndr64)
    pointer["ReferentID"] = 0x11223344
    pointer["Data"] = 0xAABBCCDD

    assert pointer.getData() == bytes.fromhex(pointer_wire)
    assert pointer.getDataReferent() == bytes.fromhex("ddccbbaa")

    parsed = _PLong(bytes.fromhex(pointer_wire), isNDR64=is_ndr64)
    assert parsed["ReferentID"] == 0x11223344


@pytest.mark.parametrize(
    "is_ndr64, wire",
    [
        (False, "00000000"),
        (True, "0000000000000000"),
    ],
)
def test_ndr_null_pointer_width(is_ndr64, wire):
    pointer = NDRPOINTERNULL(isNDR64=is_ndr64)

    assert pointer.getData() == bytes.fromhex(wire)
    assert NDRPOINTERNULL(bytes.fromhex(wire), isNDR64=is_ndr64)["Data"] == 0


@pytest.mark.parametrize(
    "is_ndr64, wire",
    [
        (False, "0100bdbd44332211"),
        (True, "01000000bdbdbdbd44332211"),
    ],
)
def test_ndr_union_discriminator_and_arm_round_trip(is_ndr64, wire):
    choice = _Choice(isNDR64=is_ndr64)
    choice["tag"] = 1
    choice["Long"] = 0x11223344

    assert choice.getData() == bytes.fromhex(wire)
    parsed = _Choice(bytes.fromhex(wire), isNDR64=is_ndr64)
    assert parsed["tag"] == 1
    assert parsed["Long"] == 0x11223344


@pytest.mark.xfail(
    strict=True,
    reason="KF-0402: NDR64 structures omit their required trailing gap",
)
def test_ndr64_structure_emits_required_trailing_gap():
    value = _TrailingGap(isNDR64=True)
    value["Long"] = 1
    value["Short"] = 2

    assert value.getData() == bytes.fromhex("0100000002000000")
