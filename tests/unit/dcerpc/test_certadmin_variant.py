"""MS-CSRA GetConfigEntry VARIANT decoding, on responses captured from a Windows CA."""

import pytest

from aiosmb.dcerpc.v5.dcom import certadmin
from aiosmb.dcerpc.v5.dcom.certadmin import parse_variant, build_variant_i4
from aiosmb.dcerpc.v5.interfaces.icertadminmgr import ICertAdminRPC

# Stub data after the ORPCTHAT header, including the trailing HRESULT.
REG_DWORD = bytes.fromhex(
    "55736572ad05a69a03000000000000000300000000000000030000004104000000000000"
)
REG_SZ = bytes.fromhex(
    "5573657201737470070000000000000008000000000000000800000099ef7f3108000000"
    "10000000080000004500530053004f0053002d004300410000000000"
)
REG_MULTI_SZ_EMPTY = bytes.fromhex(
    "55736572000000000900000000000000082000000000000000200000e17b7f3101000000"
    "010000000100800104000000000008000800000000000000b0e219290000000000000000"
    "0000000000000000"
)
# the first string has an odd length, so it is followed by alignment garbage
REG_MULTI_SZ = bytes.fromhex(
    "557365729e3c590a230000000000000008200000000000000020000091201c2901000000"
    "01000000010080010400000000000800080000000400000060f27f310400000000000000"
    "0400000001000000010000000100000001000000150000002a0000001500000031002e00"
    "32002e003800340030002e003100310033003500340039002e0031002e0039002e003100"
    "3500872214000000280000001400000031002e0033002e0036002e0031002e0034002e00"
    "31002e003300310031002e00320031002e00310014000000280000001400000031002e00"
    "33002e0036002e0031002e0034002e0031002e003300310031002e00320031002e003200"
    "09000000120000000900000032002e0035002e00320039002e0031003500000000000000"
)
# captured security descriptor value, cut down to its first 8 bytes
REG_BINARY = bytes.fromhex(
    "557365726b39a5283100000000000000112000000000000000200000911e1c2901000000"
    "010000000100800001000000000011001000000008000000103211280800000000000000"
    "08000000010014842001000000000000"
)


def test_parse_variant_dword():
    assert parse_variant(REG_DWORD) == (certadmin.VT_I4, 0x441)


def test_parse_variant_string():
    assert parse_variant(REG_SZ) == (certadmin.VT_BSTR, "ESSOS-CA")


def test_parse_variant_multi_string():
    assert parse_variant(REG_MULTI_SZ) == (
        certadmin.VT_ARRAY | certadmin.VT_BSTR,
        ["1.2.840.113549.1.9.15", "1.3.6.1.4.1.311.21.1", "1.3.6.1.4.1.311.21.2", "2.5.29.15"],
    )


def test_parse_variant_empty_multi_string():
    assert parse_variant(REG_MULTI_SZ_EMPTY) == (certadmin.VT_ARRAY | certadmin.VT_BSTR, [])


def test_parse_variant_binary():
    assert parse_variant(REG_BINARY) == (
        certadmin.VT_ARRAY | certadmin.VT_UI1,
        bytes.fromhex("0100148420010000"),
    )


def test_parse_variant_null_pointer_is_empty():
    assert parse_variant(b"\x00" * 8) == (certadmin.VT_EMPTY, None)


def test_parse_variant_truncated():
    with pytest.raises(ValueError):
        parse_variant(REG_MULTI_SZ[:-40])


def test_parse_variant_unsupported_type():
    data = bytearray(REG_DWORD)
    data[16] = data[24] = 0x05  # VT_R8
    with pytest.raises(NotImplementedError):
        parse_variant(bytes(data))


@pytest.mark.parametrize("value", [0, 1, 0x15014E, 0x40000, 0xFFFFFFFF, 0x80000001])
def test_build_variant_i4_round_trips(value):
    # at offset 0 the blob is referent + 4 pad + body, which parse_variant reads
    assert parse_variant(build_variant_i4(value)) == (certadmin.VT_I4, _as_i4(value))


@pytest.mark.parametrize("offset", list(range(8)))
def test_build_variant_i4_aligns_body_to_eight(offset):
    blob = build_variant_i4(0x15014E, offset=offset)
    # the VARIANT body is the trailing 24 bytes and must sit on an absolute
    # 8-byte boundary; its clSize (first body dword) must read back as 24
    body_abs = offset + len(blob) - 24
    assert body_abs % 8 == 0
    import struct
    assert struct.unpack_from("<L", blob, len(blob) - 24)[0] == 24


def _as_i4(value):
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value


class _FakeInterface:
    def __init__(self, values):
        self.values = values
        self.writes = []

    async def get_config_entry(self, ca_name, entry, node_path=""):
        return self.values[(ca_name, node_path, entry)], None

    async def set_config_entry_i4(self, ca_name, entry, value, node_path=""):
        self.writes.append((ca_name, node_path, entry, value))
        return True, None

    async def resubmit_request(self, ca_name, request_id):
        return certadmin.CR_DISP_ISSUED, None


def _manager(values):
    service = ICertAdminRPC()
    service.ca_name = "ESSOS-CA"
    service.iface = _FakeInterface(values)
    return service


@pytest.mark.asyncio
async def test_manager_set_edit_flags_writes_policy_node():
    service = _manager({})
    ok, err = await service.set_edit_flags(certadmin.EditFlags.EDITF_ATTRIBUTESUBJECTALTNAME2)
    assert (ok, err) == (True, None)
    assert service.iface.writes == [
        ("ESSOS-CA", certadmin.POLICY_MODULE_NODE, "EditFlags", 0x40000)
    ]


@pytest.mark.asyncio
async def test_manager_issue_pending_request_returns_disposition():
    service = _manager({})
    assert await service.issue_pending_request(58) == (certadmin.CR_DISP_ISSUED, None)


@pytest.mark.asyncio
async def test_manager_decodes_flags_and_extension_list():
    service = _manager({
        ("ESSOS-CA", "", "InterfaceFlags"): 0x441,
        ("ESSOS-CA", certadmin.POLICY_MODULE_NODE, "EditFlags"): 0x15014E,
        ("ESSOS-CA", certadmin.POLICY_MODULE_NODE, "DisableExtensionList"): ["1.3.6.1.4.1.311.25.2", ""],
    })

    flags, err = await service.get_interface_flags()
    assert err is None
    assert certadmin.InterfaceFlags.IF_ENFORCEENCRYPTICERTADMIN in flags
    assert certadmin.InterfaceFlags.IF_ENFORCEENCRYPTICERTREQUEST not in flags

    flags, err = await service.get_edit_flags()
    assert err is None
    assert certadmin.EditFlags.EDITF_ATTRIBUTESUBJECTALTNAME2 in flags

    assert await service.get_disable_extension_list() == (["1.3.6.1.4.1.311.25.2"], None)
