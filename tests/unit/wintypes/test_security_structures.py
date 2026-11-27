"""Golden parsing vectors for ACEs, ACLs, and security descriptors."""

import io
import struct

import pytest

from aiosmb.wintypes.dtyp.constrcuted_security.ace import (
    ACCESS_ALLOWED_ACE,
    ACCESS_ALLOWED_CALLBACK_ACE,
    ACCESS_ALLOWED_OBJECT_ACE,
    ACCESS_DENIED_ACE,
    ADS_ACCESS_MASK,
    ACEHeader,
    ACEReader,
    ACEType,
    AceFlags,
    SYSTEM_ALARM_ACE,
    SYSTEM_AUDIT_ACE,
)
from aiosmb.wintypes.dtyp.constrcuted_security.acl import ACL
from aiosmb.wintypes.dtyp.constrcuted_security.security_descriptor import (
    SECURITY_DESCRIPTOR,
    SE_SACL,
)


pytestmark = pytest.mark.unit

EVERYONE_SID = bytes.fromhex("010100000000000100000000")
LOCAL_SYSTEM_SID = bytes.fromhex("010100000000000512000000")
OBJECT_GUID_WIRE = bytes.fromhex("33221100554477668899aabbccddeeff")


def _simple_ace(ace_type, mask, flags=0, sid=EVERYONE_SID, trailing=b""):
    body = struct.pack("<L", mask) + sid + trailing
    return struct.pack("<BBH", ace_type, flags, 4 + len(body)) + body


def _object_ace(mask, object_flags, object_guid=b"", inherited_guid=b""):
    body = struct.pack("<LL", mask, object_flags)
    body += object_guid + inherited_guid + EVERYONE_SID
    return struct.pack(
        "<BBH",
        ACEType.ACCESS_ALLOWED_OBJECT_ACE_TYPE.value,
        0,
        4 + len(body),
    ) + body


def _acl(*aces):
    size = 8 + sum(len(ace) for ace in aces)
    return struct.pack("<BBHHH", 2, 0, size, len(aces), 0) + b"".join(aces)


def _security_descriptor():
    owner_offset = 20
    group_offset = owner_offset + len(EVERYONE_SID)
    dacl = _acl(
        _simple_ace(
            ACEType.ACCESS_ALLOWED_ACE_TYPE.value,
            ADS_ACCESS_MASK.GENERIC_READ.value,
        )
    )
    dacl_offset = group_offset + len(LOCAL_SYSTEM_SID)
    header = struct.pack(
        "<BBHLLLL",
        1,
        0,
        (SE_SACL.SE_SELF_RELATIVE | SE_SACL.SE_DACL_PRESENT).value,
        owner_offset,
        group_offset,
        0,
        dacl_offset,
    )
    return header + EVERYONE_SID + LOCAL_SYSTEM_SID + dacl


def test_ace_header_golden_vector_and_preparse_preserve_cursor():
    raw = bytes.fromhex("00431400")
    buff = io.BytesIO(raw + b"body")

    peeked = ACEHeader.pre_parse(buff)

    assert buff.tell() == 0
    assert peeked.AceType is ACEType.ACCESS_ALLOWED_ACE_TYPE
    assert peeked.AceFlags == (
        AceFlags.OBJECT_INHERIT_ACE
        | AceFlags.CONTAINER_INHERIT_ACE
        | AceFlags.SUCCESSFUL_ACCESS_ACE_FLAG
    )
    assert peeked.AceSize == 20

    parsed = ACEHeader.from_buffer(buff)
    assert parsed.AceType is peeked.AceType
    assert parsed.AceFlags == peeked.AceFlags
    assert parsed.AceSize == peeked.AceSize
    assert buff.read() == b"body"


@pytest.mark.parametrize(
    "ace_type,expected_class",
    [
        (ACEType.ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_ACE),
        (ACEType.ACCESS_DENIED_ACE_TYPE, ACCESS_DENIED_ACE),
        (ACEType.SYSTEM_AUDIT_ACE_TYPE, SYSTEM_AUDIT_ACE),
        (ACEType.SYSTEM_ALARM_ACE_TYPE, SYSTEM_ALARM_ACE),
    ],
)
def test_simple_ace_types_parse_golden_vector(ace_type, expected_class):
    raw = _simple_ace(
        ace_type.value,
        ADS_ACCESS_MASK.READ_PROP.value | ADS_ACCESS_MASK.GENERIC_READ.value,
        AceFlags.OBJECT_INHERIT_ACE.value | AceFlags.CONTAINER_INHERIT_ACE.value,
    )
    buff = io.BytesIO(raw + b"tail")

    ace = ACEReader.from_buffer(buff)

    assert isinstance(ace, expected_class)
    assert ace.Header.AceType is ace_type
    assert ace.Header.AceSize == len(raw)
    assert ace.Header.AceFlags == (
        AceFlags.OBJECT_INHERIT_ACE | AceFlags.CONTAINER_INHERIT_ACE
    )
    assert ace.Mask == ADS_ACCESS_MASK.READ_PROP | ADS_ACCESS_MASK.GENERIC_READ
    assert str(ace.Sid) == "S-1-1-0"
    assert buff.read() == b"tail"


def test_callback_ace_keeps_application_data_inside_ace_boundary():
    application_data = bytes.fromhex("deadbeef")
    raw = _simple_ace(
        ACEType.ACCESS_ALLOWED_CALLBACK_ACE_TYPE.value,
        ADS_ACCESS_MASK.CONTROL_ACCESS.value,
        sid=EVERYONE_SID,
        trailing=application_data,
    )
    buff = io.BytesIO(raw + b"outside")

    ace = ACEReader.from_buffer(buff)

    assert isinstance(ace, ACCESS_ALLOWED_CALLBACK_ACE)
    assert ace.ApplicationData == application_data
    assert str(ace.Sid) == "S-1-1-0"
    assert buff.read() == b"outside"


def test_object_ace_without_optional_guids_parses():
    raw = _object_ace(ADS_ACCESS_MASK.READ_PROP.value, 0)

    ace = ACEReader.from_buffer(io.BytesIO(raw))

    assert isinstance(ace, ACCESS_ALLOWED_OBJECT_ACE)
    assert ace.ObjectType is None
    assert ace.InheritedObjectType is None
    assert str(ace.Sid) == "S-1-1-0"


@pytest.mark.xfail(
    strict=True,
    reason="KF-0303: object ACE parser references an undefined GUID symbol",
)
def test_object_ace_with_guid_parses_canonical_identifier():
    raw = _object_ace(
        ADS_ACCESS_MASK.READ_PROP.value,
        1,
        object_guid=OBJECT_GUID_WIRE,
    )

    ace = ACEReader.from_buffer(io.BytesIO(raw))

    assert str(ace.ObjectType) == "00112233-4455-6677-8899-aabbccddeeff"
    assert ace.InheritedObjectType is None
    assert str(ace.Sid) == "S-1-1-0"


def test_ace_reader_rejects_unknown_and_unimplemented_types():
    with pytest.raises(ValueError):
        ACEReader.from_buffer(io.BytesIO(bytes.fromhex("ff000400")))

    with pytest.raises(Exception, match="not implemented"):
        ACEReader.from_buffer(
            io.BytesIO(
                struct.pack(
                    "<BBH",
                    ACEType.ACCESS_ALLOWED_COMPOUND_ACE_TYPE.value,
                    0,
                    4,
                )
            )
        )


@pytest.mark.xfail(
    strict=True,
    reason="KF-0307: ACE parser accepts an empty buffer as an allowed ACE",
)
def test_ace_reader_rejects_truncated_wire_data():
    with pytest.raises(Exception):
        ACEReader.from_buffer(io.BytesIO(b""))


def test_acl_parses_multiple_aces_and_stops_at_declared_boundaries():
    allowed = _simple_ace(
        ACEType.ACCESS_ALLOWED_ACE_TYPE.value,
        ADS_ACCESS_MASK.GENERIC_READ.value,
    )
    denied = _simple_ace(
        ACEType.ACCESS_DENIED_ACE_TYPE.value,
        ADS_ACCESS_MASK.WRITE_PROP.value,
    )
    raw = _acl(allowed, denied)
    buff = io.BytesIO(raw + b"tail")

    acl = ACL.from_buffer(buff)

    assert acl.AclRevision == 2
    assert acl.Sbz1 == 0
    assert acl.AclSize == len(raw)
    assert acl.AceCount == 2
    assert acl.Sbz2 == 0
    assert isinstance(acl.aces[0], ACCESS_ALLOWED_ACE)
    assert isinstance(acl.aces[1], ACCESS_DENIED_ACE)
    assert acl.aces[0].Mask == ADS_ACCESS_MASK.GENERIC_READ
    assert acl.aces[1].Mask == ADS_ACCESS_MASK.WRITE_PROP
    assert "ACCESS_ALLOWED_ACE" in str(acl)
    assert buff.read() == b"tail"


def test_empty_acl_header_is_a_valid_zero_ace_acl():
    raw = _acl()

    acl = ACL.from_buffer(io.BytesIO(raw))

    assert acl.AclSize == 8
    assert acl.AceCount == 0
    assert acl.aces == []


@pytest.mark.xfail(
    strict=True,
    reason="KF-0308: ACL parser accepts a truncated fixed header",
)
def test_acl_rejects_truncated_wire_data():
    with pytest.raises(Exception):
        ACL.from_buffer(io.BytesIO(b"\x02\x00\x08"))


def test_security_descriptor_parses_self_relative_offsets():
    raw = _security_descriptor()

    descriptor = SECURITY_DESCRIPTOR.from_bytes(raw)

    assert descriptor.Revision == 1
    assert descriptor.Sbz1 == 0
    assert descriptor.Control == SE_SACL.SE_SELF_RELATIVE | SE_SACL.SE_DACL_PRESENT
    assert str(descriptor.Owner) == "S-1-1-0"
    assert str(descriptor.Group) == "S-1-5-18"
    assert descriptor.Sacl is None
    assert descriptor.Dacl.AceCount == 1
    assert descriptor.Dacl.aces[0].Mask == ADS_ACCESS_MASK.GENERIC_READ
    rendered = str(descriptor)
    assert "Owner : S-1-1-0" in rendered
    assert "Group : S-1-5-18" in rendered


def test_security_descriptor_allows_null_component_offsets():
    raw = struct.pack(
        "<BBHLLLL",
        1,
        0,
        SE_SACL.SE_SELF_RELATIVE.value,
        0,
        0,
        0,
        0,
    )

    descriptor = SECURITY_DESCRIPTOR.from_bytes(raw)

    assert descriptor.Owner is None
    assert descriptor.Group is None
    assert descriptor.Sacl is None
    assert descriptor.Dacl is None


@pytest.mark.xfail(
    strict=True,
    reason="KF-0309: security descriptor parser accepts a truncated header",
)
def test_security_descriptor_rejects_truncated_wire_data():
    with pytest.raises(Exception):
        SECURITY_DESCRIPTOR.from_bytes(b"\x01\x00")


@pytest.mark.xfail(
    strict=True,
    reason="KF-0313: security descriptor offsets ignore buffer start position",
)
def test_security_descriptor_offsets_are_relative_to_structure_start():
    raw = _security_descriptor()
    buff = io.BytesIO(b"lead" + raw + b"tail")
    buff.seek(4)

    descriptor = SECURITY_DESCRIPTOR.from_buffer(buff)

    assert str(descriptor.Owner) == "S-1-1-0"
    assert str(descriptor.Group) == "S-1-5-18"
    assert descriptor.Dacl.AceCount == 1
