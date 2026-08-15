"""Stable fixture coverage for DPAPI-NG, GKDI, and event blob structures."""

import io
import json
from pathlib import Path
import uuid

import pytest

from aiosmb.dcerpc.v5 import even, even6
from aiosmb.dcerpc.v5.common.dpapi_ng._crypto import (
    ECDHKey,
    FFCDHKey,
    FFCDHParameters,
    GroupKeyEnvelope,
    KDFParameters,
)
from aiosmb.dcerpc.v5.common.dpapi_ng._security_descriptor import (
    ace_to_bytes,
    acl_to_bytes,
    sid_to_bytes,
)
from aiosmb.dcerpc.v5.common.dpapi_ng.blob import (
    KeyIdentifier,
    ProtectionDescriptor,
    ProtectionDescriptorType,
    SIDDescriptor,
)
from aiosmb.dcerpc.v5.common.even6 import binxml
from aiosmb.dcerpc.v5.common.even6.resultset import RESULT_SET as ParsedResultSet


pytestmark = pytest.mark.unit

ROOT_KEY_ID = uuid.UUID("00112233-4455-6677-8899-aabbccddeeff")
TARGET_SID = "S-1-5-21-1-2-3-1001"


@pytest.fixture(scope="module")
def wire_vectors():
    fixture_path = (
        Path(__file__).parents[2] / "fixtures" / "dcerpc" / "wire_vectors.json"
    )
    with fixture_path.open("r", encoding="utf-8") as fixture_file:
        values = json.load(fixture_file)
    return {
        category: {
            name: bytes.fromhex(value)
            for name, value in category_values.items()
        }
        for category, category_values in values.items()
    }


def _key_identifier():
    return KeyIdentifier(
        version=1,
        flags=1,
        l0=10,
        l1=20,
        l2=30,
        root_key_identifier=ROOT_KEY_ID,
        key_info=bytes.fromhex("deadbeef"),
        domain_name="example.test",
        forest_name="forest.test",
    )


def _kdf_parameters():
    return KDFParameters(hash_name="SHA256")


def _ffcdh_parameters():
    return FFCDHParameters(
        key_length=2,
        field_order=0x0101,
        generator=2,
    )


def _group_key_envelope():
    return GroupKeyEnvelope(
        version=1,
        flags=0,
        l0=10,
        l1=20,
        l2=30,
        root_key_identifier=ROOT_KEY_ID,
        kdf_algorithm="SP800_108_CTR_HMAC",
        kdf_parameters=_kdf_parameters().pack(),
        secret_algorithm="DH",
        secret_parameters=_ffcdh_parameters().pack(),
        private_key_length=256,
        public_key_length=512,
        domain_name="example.test",
        forest_name="forest.test",
        l1_key=bytes.fromhex("00112233"),
        l2_key=bytes.fromhex("aabbccdd"),
    )


def test_key_identifier_fixture_round_trip(wire_vectors):
    expected = _key_identifier()
    wire = wire_vectors["dpapi_ng_gkdi"]["key_identifier"]

    assert expected.pack() == wire
    assert KeyIdentifier.unpack(wire) == expected
    assert expected.is_public_key is True


def test_key_identifier_rejects_invalid_magic(wire_vectors):
    wire = bytearray(wire_vectors["dpapi_ng_gkdi"]["key_identifier"])
    wire[4:8] = b"FAIL"

    with pytest.raises(ValueError, match="magic identifier is invalid"):
        KeyIdentifier.unpack(wire)


def test_sid_binary_and_access_control_entry_contracts():
    sid = sid_to_bytes(TARGET_SID)
    expected_sid = bytes.fromhex(
        "010500000000000515000000010000000200000003000000e9030000"
    )

    assert sid == expected_sid
    ace = ace_to_bytes(TARGET_SID, 3)
    assert ace[:8] == bytes.fromhex("0000240003000000")
    assert ace[8:] == expected_sid

    acl = acl_to_bytes([ace])
    assert acl[:8] == bytes.fromhex("02002c0001000000")
    assert acl[8:] == ace


@pytest.mark.parametrize(
    "sid",
    [
        "",
        "S-1-5",
        "not-a-sid",
        "S-1-5-21-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15-16",
    ],
)
def test_sid_conversion_rejects_invalid_text(sid):
    with pytest.raises(ValueError, match="not a valid SID string"):
        sid_to_bytes(sid)


def test_sid_descriptor_target_security_descriptor_fixture(wire_vectors):
    descriptor = SIDDescriptor(TARGET_SID)

    assert descriptor.type is ProtectionDescriptorType.SID
    assert descriptor.get_target_sd() == (
        wire_vectors["dpapi_ng_gkdi"]["target_security_descriptor"]
    )
    assert ProtectionDescriptor.parse(TARGET_SID) == descriptor


def test_protection_descriptor_unpacks_asn1_native_shape():
    native_value = {
        "0": ProtectionDescriptorType.SID.value,
        "1": {"0": {"0": {"0": "SID", "1": TARGET_SID}}},
    }

    assert ProtectionDescriptor.unpack(native_value) == SIDDescriptor(TARGET_SID)

    native_value["1"]["0"]["0"]["0"] = "SDDL"
    with pytest.raises(ValueError, match="is unsupported"):
        ProtectionDescriptor.unpack(native_value)


def test_kdf_parameters_fixture_and_hash_selection(wire_vectors):
    expected = _kdf_parameters()
    wire = wire_vectors["dpapi_ng_gkdi"]["kdf_parameters"]

    assert expected.pack() == wire
    assert KDFParameters.unpack(wire) == expected
    assert expected.hash_algorithm.name == "sha256"


@pytest.mark.parametrize("hash_name", ["SHA1", "SHA256", "SHA384", "SHA512"])
def test_kdf_parameters_supported_hash_algorithms(hash_name):
    parameters = KDFParameters(hash_name)

    assert parameters.hash_algorithm.name == hash_name.lower()
    assert KDFParameters.unpack(parameters.pack()) == parameters


def test_kdf_parameters_reject_invalid_magic_and_unknown_hash():
    with pytest.raises(ValueError, match="magic identifier is invalid"):
        KDFParameters.unpack(b"\xff" * 32)

    with pytest.raises(NotImplementedError, match="Unsupported hash algorithm"):
        KDFParameters("MD5").hash_algorithm


def test_ffcdh_parameters_fixture_round_trip(wire_vectors):
    expected = _ffcdh_parameters()
    wire = wire_vectors["dpapi_ng_gkdi"]["ffcdh_parameters"]

    assert expected.pack() == wire
    assert FFCDHParameters.unpack(wire) == expected


def test_ffcdh_public_key_fixture_round_trip(wire_vectors):
    expected = FFCDHKey(
        key_length=2,
        field_order=0x0101,
        generator=2,
        public_key=0x0100,
    )
    wire = wire_vectors["dpapi_ng_gkdi"]["ffcdh_key"]

    assert expected.pack() == wire
    assert FFCDHKey.unpack(wire) == expected


def test_ecdh_public_key_fixture_round_trip(wire_vectors):
    expected = ECDHKey(
        curve_name="P256",
        key_length=4,
        x=0x01020304,
        y=0xA0B0C0D0,
    )
    wire = wire_vectors["dpapi_ng_gkdi"]["ecdh_key"]

    assert expected.pack() == wire
    assert ECDHKey.unpack(wire) == expected
    curve, hash_algorithm = expected.curve_and_hash
    assert curve.name == "secp256r1"
    assert hash_algorithm.name == "sha256"


def test_ecdh_key_rejects_unknown_curve_for_pack_and_unpack():
    with pytest.raises(ValueError, match="Unknown curve"):
        ECDHKey("P999", 4, 1, 2).pack()

    with pytest.raises(ValueError, match="unknown curve"):
        ECDHKey.unpack(b"FAIL" + b"\x00" * 12)


@pytest.mark.parametrize(
    "key_type, fixture_name, magic_offset",
    [
        (FFCDHParameters, "ffcdh_parameters", 4),
        (FFCDHKey, "ffcdh_key", 0),
    ],
)
def test_ffcdh_structures_reject_invalid_magic(
    wire_vectors, key_type, fixture_name, magic_offset
):
    wire = bytearray(wire_vectors["dpapi_ng_gkdi"][fixture_name])
    wire[magic_offset:magic_offset + 4] = b"FAIL"

    with pytest.raises(ValueError, match="magic identifier is invalid"):
        key_type.unpack(wire)


def test_group_key_envelope_fixture_round_trip(wire_vectors):
    expected = _group_key_envelope()
    wire = wire_vectors["dpapi_ng_gkdi"]["group_key_envelope"]

    assert expected.pack() == wire
    assert GroupKeyEnvelope.unpack(wire) == expected
    assert expected.is_public_key is False


def test_group_key_envelope_rejects_invalid_magic(wire_vectors):
    wire = bytearray(wire_vectors["dpapi_ng_gkdi"]["group_key_envelope"])
    wire[4:8] = b"FAIL"

    with pytest.raises(ValueError, match="magic identifier is invalid"):
        GroupKeyEnvelope.unpack(wire)


@pytest.mark.parametrize("is_ndr64", [False, True])
def test_event_descriptor_fixture_round_trip(wire_vectors, is_ndr64):
    wire = wire_vectors["event"]["event_descriptor"]
    descriptor = even6.EVENT_DESCRIPTOR(wire, isNDR64=is_ndr64)

    assert descriptor["Id"] == 0x1234
    assert descriptor["Version"] == 1
    assert descriptor["Channel"] == 2
    assert descriptor["LevelSeverity"] == 3
    assert descriptor["Opcode"] == 4
    assert descriptor["Task"] == 0x5678
    assert descriptor["Keyword"] == 0x11223344
    assert descriptor.getData() == wire


def test_event_context_handle_fixture_round_trip(wire_vectors):
    wire = wire_vectors["event"]["context_handle"]

    legacy = even.IELF_HANDLE(wire)
    modern = even6.CONTEXT_HANDLE_LOG_HANDLE(wire)

    assert legacy["Data"] == bytes(range(20))
    assert modern["Data"] == bytes(range(20))
    assert legacy.getData() == wire
    assert modern.getData() == wire
    assert legacy.getAlignment() == 1


@pytest.mark.xfail(
    strict=True,
    reason=(
        "KF-0405: EVEN6 context handles report the 20-byte field size "
        "instead of their declared byte alignment"
    ),
)
def test_even6_context_handle_uses_declared_byte_alignment():
    assert even6.CONTEXT_HANDLE_LOG_HANDLE().getAlignment() == 1


def test_even6_result_set_fixture_parses_all_sections(wire_vectors):
    wire = wire_vectors["event"]["result_set"]

    result = ParsedResultSet.from_bytes(wire)

    assert result.totalSize == len(wire) == 32
    assert result.headerSize == 20
    assert result.eventOffset == 20
    assert result.bookmarkOffset == 30
    assert result.binXmlSize == 4
    assert result.eventData == bytes.fromhex("0f010000")
    assert result.numberOfSubqueryIDs == 2
    assert result.subqueryIDs == bytes.fromhex("0307")
    assert result.bookMarkData == b"BM"


def test_legacy_event_record_fixture_serialization(wire_vectors):
    record = even.EVENTLOGRECORD()
    fields = {
        "Length": 72,
        "Reserved": 0x654C664C,
        "RecordNumber": 7,
        "TimeGenerated": 1,
        "TimeWritten": 2,
        "EventID": 0x1001,
        "EventType": even.EVENTLOG_INFORMATION_TYPE,
        "NumStrings": 0,
        "EventCategory": 3,
        "ReservedFlags": 0,
        "ClosingRecordNumber": 0,
        "StringOffset": 0,
        "UserSidLength": 0,
        "UserSidOffset": 0,
        "DataLength": 0,
        "DataOffset": 0,
        "SourceName": "Source",
        "Computername": "Host",
        "UserSidPadding": b"",
        "UserSid": b"",
        "Strings": b"",
        "Data": b"",
        "Padding": b"",
        "Length2": 72,
    }
    for name, value in fields.items():
        record[name] = value

    assert record.getData() == wire_vectors["event"]["legacy_event_record"]


@pytest.mark.xfail(
    strict=True,
    reason=(
        "KF-0404: EVENTLOGRECORD parsing lets the unbounded Strings field "
        "consume Length2"
    ),
)
def test_legacy_event_record_fixture_round_trip(wire_vectors):
    wire = wire_vectors["event"]["legacy_event_record"]

    parsed = even.EVENTLOGRECORD(wire)

    assert parsed["Length"] == len(wire)
    assert parsed["SourceName"] == "Source"
    assert parsed["Computername"] == "Host"
    assert parsed["Strings"] == b""
    assert parsed["Length2"] == len(wire)


def test_binxml_fragment_header_and_name_parsing():
    header = binxml.parse_next(io.BytesIO(bytes.fromhex("0f010000")))
    name = binxml.Name.from_buffer(
        io.BytesIO(bytes.fromhex("3412040054006500730074000000"))
    )

    assert isinstance(header, binxml.FragmentHeader)
    assert header.FragmentHeaderToken == b"\x0f"
    assert header.major == 1
    assert header.minor == 0
    assert header.flags == 0
    assert name.NameHash == 0x1234
    assert name.NameNumChars == 4
    assert name.value == "Test"


def test_binxml_value_spec_and_value_text_parsing():
    instance_data = binxml.TemplateInstanceData.from_buffer(
        io.BytesIO(bytes.fromhex("010000000400080078563412"))
    )
    value_text = binxml.parse_next(
        io.BytesIO(
            b"\x05\x01"
            + (5).to_bytes(2, byteorder="little")
            + "Hello".encode("utf-16-le")
        )
    )

    assert instance_data.ValueSpec.NumValues == 1
    entry = instance_data.ValueSpec.ValueSpecEntries[0]
    assert entry.ValueByteLength == 4
    assert entry.ValueType is binxml.ValueType.UInt32Type
    assert instance_data.Values == [0x12345678]
    assert isinstance(value_text, binxml.ValueText)
    assert value_text.StringType == b"\x01"
    assert value_text.value == "Hello"
    assert value_text.to_xml() == "Hello"


@pytest.mark.parametrize(
    "wire, value_type, expected",
    [
        (b"", binxml.ValueType.NullType, ""),
        ("Hello".encode("utf-16-le"), binxml.ValueType.StringType, "Hello"),
        (b"ansi", binxml.ValueType.AnsiStringType, "ansi"),
        (b"\xfe", binxml.ValueType.Int8Type, -2),
        (b"\xfe", binxml.ValueType.UInt8Type, 254),
        (bytes.fromhex("feff"), binxml.ValueType.Int16Type, -2),
        (bytes.fromhex("feffffff"), binxml.ValueType.Int32Type, -2),
        (bytes.fromhex("feffffffffffffff"), binxml.ValueType.Int64Type, -2),
        (bytes.fromhex("78563412"), binxml.ValueType.UInt32Type, 0x12345678),
        (b"\x01\x00\x00\x00", binxml.ValueType.BoolType, True),
        (bytes.fromhex("deadbeef"), binxml.ValueType.BinaryType,
         bytes.fromhex("deadbeef")),
        (bytes.fromhex("78563412"), binxml.ValueType.SizeTType, "0x12345678"),
        (bytes.fromhex("78563412"), binxml.ValueType.HexInt32Type,
         "0x12345678"),
    ],
)
def test_binxml_scalar_value_decoding(wire, value_type, expected):
    assert binxml.decode_val(wire, value_type) == expected


def test_binxml_rejects_unexpected_token_and_unknown_value_type():
    with pytest.raises(Exception, match="parse_next error"):
        binxml.parse_next(
            io.BytesIO(b"\x00"),
            expected=(binxml.FragmentHeader,),
        )

    with pytest.raises(Exception, match="Unknown format"):
        binxml.decode_val(b"", object())
