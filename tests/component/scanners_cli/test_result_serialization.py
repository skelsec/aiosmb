"""Scanner result formatting contracts exercised without an SMB peer."""

import datetime
import json
import sys
from types import SimpleNamespace

import pytest

if sys.version_info < (3, 9):
    pytest.skip("blocked by KF-0107", allow_module_level=True)

from aiosmb.commons.scanner.common.comms import EnumResultStatus as CommonStatus
from aiosmb.examples.scancommons.internal import (
    EnumProgress,
    EnumResultStatus as ExampleStatus,
)
from aiosmb.examples.scanners.smbadmin import SMBAdminRes
from aiosmb.examples.scanners.smbbrute import SMBBruteForceRes
from aiosmb.examples.scanners.smbfile import SMBFileRes
from aiosmb.examples.scanners.smbfinger import SMBFingerRes
from aiosmb.examples.scanners.smbencryption import SMBEncryptionRes
from aiosmb.examples.scanners.smbiface import SMBInterfaceRes
from aiosmb.examples.scanners.smbprintnightmare import SMBPrintnightmareRes
from aiosmb.examples.scanners.smbproto import SMBProtocolRes
from aiosmb.examples.scanners.smbregsession import SMBRegSessionRes
from aiosmb.examples.scanners.smbsession import SMBSessionRes
from aiosmb.examples.scanners.smbshare import SMBShareRes
from aiosmb.examples.smbshareenum import EnumResultFinal


pytestmark = pytest.mark.component


class FakeSecurityDescriptor:
    def to_sddl(self):
        return "O:BAG:BAD:(A;;FA;;;SY)"

    def to_bytes(self):
        return b"\x01\x02\x03"


def test_protocol_result_normalizes_wildcard_and_serializes() -> None:
    result = SMBProtocolRes("WILDCARD", True, False)

    assert result.get_header() == ["PROTO", "SIGN_ENABLED", "SIGN_ENFORCED"]
    assert result.to_line("|") == "SMB1|True|False"
    assert result.to_dict() == {
        "PROTO": "SMB1",
        "SIGN_ENABLED": True,
        "SIGN_ENFORCED": False,
    }


def test_encryption_result_keeps_header_line_and_dict_in_sync() -> None:
    result = SMBEncryptionRes(
        "SMB311",
        True,
        True,
        False,
        "CLEAR_SESSION_ACCEPTED",
    )

    assert result.get_header() == [
        "DIALECT",
        "ENCRYPTION_SUPPORTED",
        "SESSION_ENCRYPTION_REQUIRED",
        "ENCRYPTION_ENFORCED",
        "PROBE_STATUS",
    ]
    assert result.to_line("|") == (
        "SMB311|True|True|False|CLEAR_SESSION_ACCEPTED"
    )
    assert result.to_dict() == {
        "DIALECT": "SMB311",
        "ENCRYPTION_SUPPORTED": True,
        "SESSION_ENCRYPTION_REQUIRED": True,
        "ENCRYPTION_ENFORCED": False,
        "PROBE_STATUS": "CLEAR_SESSION_ACCEPTED",
    }


@pytest.mark.parametrize(
    "result,expected_header,expected_line,expected_dict",
    [
        (
            SMBAdminRes(True, False, False),
            ["SHARE", "SERVICE", "REGISTRY", "ADMIN"],
            "True|False|False|True",
            {
                "SHARE": True,
                "SERVICE": False,
                "REGISTRY": False,
                "ADMIN": True,
            },
        ),
        (
            SMBInterfaceRes("192.0.2.10"),
            ["interface"],
            "192.0.2.10",
            {"interface": "192.0.2.10"},
        ),
        (
            SMBSessionRes(SimpleNamespace(username="alice", ip_addr="192.0.2.20")),
            ["USERNAME", "IP"],
            "alice|192.0.2.20",
            {"USERNAME": "alice", "IP": "192.0.2.20"},
        ),
        (
            SMBBruteForceRes("EXAMPLE", "alice", "secret"),
            ["DOMAIN", "USERNAME", "PASSWORD"],
            "EXAMPLE|alice|secret",
            {"DOMAIN": "EXAMPLE", "USERNAME": "alice", "PASSWORD": "secret"},
        ),
        (
            SMBPrintnightmareRes("DIRECT", True),
            ["VULNTYPE", "IS_VULNERABLE"],
            "DIRECT|True",
            {"VULNTYPE": "DIRECT", "IS_VULNERABLE": True},
        ),
    ],
)
def test_scalar_results_keep_header_line_and_dict_in_sync(
    result, expected_header, expected_line, expected_dict
) -> None:
    assert result.get_header() == expected_header
    assert result.to_line("|") == expected_line
    assert result.to_dict() == expected_dict


def test_fingerprint_result_delegates_each_serialization_format() -> None:
    server_info = SimpleNamespace(
        to_json=lambda: '{"os": "Windows"}',
        to_tsv=lambda separator: "Windows{}10".format(separator),
        to_dict=lambda: {"os": "Windows", "version": "10"},
    )
    result = SMBFingerRes(server_info)

    assert result.to_json() == '{"os": "Windows"}'
    assert result.to_line("|") == "Windows|10"
    assert result.to_dict() == {"os": "Windows", "version": "10"}


def test_file_result_serializes_metadata_in_all_formats() -> None:
    created = datetime.datetime(2026, 8, 14, 7, 30, 0)
    file_obj = SimpleNamespace(
        unc_path=r"\\server\share\report.txt",
        creation_time=created,
        size=1536,
        security_descriptor=FakeSecurityDescriptor(),
    )

    result = SMBFileRes(file_obj, "file", None)

    assert result.get_header() == [
        "otype",
        "path",
        "creationtime",
        "size",
        "sizefmt",
        "sddl",
    ]
    assert result.to_line("|") == (
        r"file|\\server\share\report.txt|2026-08-14T07:30:00|1536|"
        "1.5KiB|O:BAG:BAD:(A;;FA;;;SY)"
    )
    assert result.to_dict() == {
        "otype": "file",
        "path": r"\\server\share\report.txt",
        "creationtime": "2026-08-14T07:30:00",
        "size": 1536,
        "sizefmt": "1.5KiB",
        "sddl": "O:BAG:BAD:(A;;FA;;;SY)",
    }


def test_share_result_serializes_security_descriptor_and_error_rows() -> None:
    share = SimpleNamespace(
        unc_path=r"\\server\public",
        remark="Public files",
        maximal_access=0x1F01FF,
        security_descriptor=FakeSecurityDescriptor(),
    )

    success = SMBShareRes(share, True, None)
    failure = SMBShareRes(share, None, RuntimeError("access denied"))

    assert success.to_line("|") == (
        r"\\server\public|True|Public files|2032127|"
        "O:BAG:BAD:(A;;FA;;;SY)"
    )
    assert success.to_dict()["sdhex"] == "010203"
    assert failure.to_line("|") == (
        r"\\server\public||||access denied"
    )
    assert failure.to_dict() == {
        "path": r"\\server\public",
        "writable": "",
        "description": "",
        "access": "",
        "sddl": "access denied",
        "sdhex": "",
    }


def test_share_enumerator_result_round_trips_json_and_tsv() -> None:
    created = datetime.datetime(2026, 8, 14, 8, 0, 0)
    file_obj = SimpleNamespace(
        unc_path=r"\\server\share\data.bin",
        creation_time=created,
        size=1024,
        security_descriptor=FakeSecurityDescriptor(),
    )
    result = EnumResultFinal(file_obj, "file", None, "server", "target-1")

    assert result.to_tsv().split("\t") == [
        "server",
        "target-1",
        "file",
        r"\\server\share\data.bin",
        "2026-08-14 08:00:00",
        "1024",
        "1.0KiB",
        "O:BAG:BAD:(A;;FA;;;SY)",
        "None",
    ]
    assert json.loads(result.to_json()) == {
        "target": "server",
        "target_id": "target-1",
        "path": r"\\server\share\data.bin",
        "creationtime": "2026-08-14T08:00:00",
        "size": 1024,
        "sizefmt": "1.0KiB",
        "sddl": "O:BAG:BAD:(A;;FA;;;SY)",
        "otype": "file",
        "err": None,
    }


def test_progress_result_is_omitted_from_tsv() -> None:
    progress = EnumProgress(5, 3, True, "server-3")
    result = EnumResultFinal(progress, "progress", None, "server-3", "target-3")

    assert result.to_tsv() == ""


@pytest.mark.xfail(
    strict=True,
    reason="KF-0640: finished scanner status is misspelled in serialized form",
)
@pytest.mark.parametrize("status", [CommonStatus.FINISHED, ExampleStatus.FINISHED])
def test_finished_status_serializes_with_canonical_spelling(status) -> None:
    assert status.value == "FINISHED"


@pytest.mark.xfail(
    strict=True,
    reason="KF-0641: registry-session header does not describe its two fields",
)
def test_registry_session_header_matches_line_and_dict_fields() -> None:
    result = SMBRegSessionRes("S-1-5-21-1", "EXAMPLE\\alice")

    assert result.get_header() == ["SID", "USERNAME"]
    assert result.to_line("|") == r"S-1-5-21-1|EXAMPLE\alice"
    assert list(result.to_dict()) == result.get_header()


@pytest.mark.xfail(
    strict=True,
    reason="KF-0642: progress output reverses finished and total counts",
)
def test_progress_result_displays_finished_count_before_total() -> None:
    progress = EnumProgress(5, 3, True, "server-3")
    result = EnumResultFinal(progress, "progress", None, "server-3", "target-3")

    assert str(result) == "[P][3/5][True] server-3"
