"""Focused contracts for small, reusable commons utilities."""

import datetime
import enum
import importlib
import ipaddress
import json
import re
import sys
from xml.parsers.expat import ExpatError

import pytest
from winacl.dtyp.ace import FILE_ACCESS_MASK

from aiosmb.commons.utils.decorators import red, red_gen, rr, rr_gen
from aiosmb.commons.utils.faccess import (
    faccess_mask_to_unix,
    faccess_match,
)
from aiosmb.commons.utils.fmtsize import size_to_bytes, sizeof_fmt
from aiosmb.commons.utils.glob2re import glob2re
from aiosmb.commons.utils.hexdump import hexdump
from aiosmb.commons.utils.ts2dt import datetime2timestamp, timestamp2datetime
from aiosmb.commons.utils.univeraljson import UniversalEncoder


pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "pattern,matching,not_matching",
    [
        ("*.txt", ["a.txt", ".txt"], ["a.bin", "dir/a.txt"]),
        ("file?.[ch]", ["file1.c", "fileA.h"], ["file10.c", "file1.py"]),
        ("[!a-c]*", ["z", "z.txt"], ["a", "c.txt"]),
        ("literal[", ["literal["], ["literal"]),
    ],
)
def test_glob_translation_matches_path_segment_semantics(
    pattern: str, matching: list, not_matching: list
) -> None:
    translated = re.compile(glob2re(pattern))

    assert all(translated.fullmatch(value) for value in matching)
    assert not any(translated.fullmatch(value) for value in not_matching)


def test_hexdump_matches_golden_layout_and_ascii_filtering() -> None:
    assert hexdump(b"ABC\x00\x7f", length=4, sep="?") == (
        "00000000:  41 42  43 00   |ABC?|\n"
        "00000004:  7f             |?|"
    )
    assert hexdump(b"") == ""


@pytest.mark.parametrize(
    "value,expected",
    [
        (None, ""),
        (0, "0.0B"),
        (1023, "1023.0B"),
        (1024, "1.0KiB"),
        (-1536, "-1.5KiB"),
        (1024 ** 3, "1.0GiB"),
    ],
)
def test_sizeof_fmt_boundaries(value: int, expected: str) -> None:
    assert sizeof_fmt(value) == expected


@pytest.mark.parametrize(
    "text,expected",
    [
        ("", None),
        (None, None),
        ("0", 0),
        ("1024", 1024),
        ("1K", 1024),
        ("1.5M", 1572864),
        ("2g", 2147483648),
        ("-2K", -2048),
    ],
)
def test_size_parser_handles_supported_units(text: str, expected: int) -> None:
    assert size_to_bytes(text) == expected


@pytest.mark.parametrize("text", ["KB", "1KB", "one", " 1K "])
def test_size_parser_rejects_malformed_values(text: str) -> None:
    with pytest.raises(ValueError, match="Invalid size format"):
        size_to_bytes(text)


@pytest.mark.xfail(
    strict=True,
    reason="KF-0105: terabyte size suffix is parsed using the wrong replacement",
)
def test_size_parser_supports_declared_terabyte_suffix() -> None:
    assert size_to_bytes("1.5T") == int(1.5 * 1024 ** 4)


@pytest.mark.parametrize(
    "moment",
    [
        datetime.datetime(1601, 1, 1),
        datetime.datetime(1970, 1, 1),
        datetime.datetime(2024, 2, 29, 23, 59, 59, 123456),
    ],
)
def test_windows_timestamp_round_trip(moment: datetime.datetime) -> None:
    assert timestamp2datetime(datetime2timestamp(moment)) == moment


@pytest.mark.xfail(
    strict=True,
    reason="KF-0106: FILETIME conversion overflows at datetime upper boundary",
)
def test_windows_timestamp_round_trip_at_datetime_upper_boundary() -> None:
    moment = datetime.datetime(9999, 12, 31, 23, 59, 59, 999999)

    assert timestamp2datetime(datetime2timestamp(moment)) == moment


def test_windows_epoch_conversion_matches_golden_filetime() -> None:
    encoded = bytes.fromhex("00803ed5deb19d01")

    assert datetime2timestamp(datetime.datetime(1970, 1, 1)) == encoded
    assert timestamp2datetime(encoded) == datetime.datetime(1970, 1, 1)


@pytest.mark.xfail(
    sys.version_info < (3, 9),
    strict=True,
    reason="KF-0107: timestamp utility evaluates Python 3.9-only annotations",
)
def test_timestamp_utility_imports_on_python_38() -> None:
    module = importlib.import_module("aiosmb.commons.utils.tschecker")

    assert callable(module.tssplit)


@pytest.mark.parametrize(
    "path,expected",
    [
        ("report.txt", ("report.txt", None)),
        (
            "report.txt@GMT-2024.01.02-03.04.05",
            ("report.txt", "@GMT-2024.01.02-03.04.05"),
        ),
        (
            "a@b@GMT-2024.01.02-03.04.05",
            ("a@b", "@GMT-2024.01.02-03.04.05"),
        ),
        (
            "report.txt@GMT-2024-01-02",
            ("report.txt@GMT-2024-01-02", None),
        ),
    ],
)
@pytest.mark.xfail(
    sys.version_info < (3, 9),
    strict=True,
    reason="KF-0107: timestamp utility evaluates Python 3.9-only annotations",
)
def test_shadow_copy_timestamp_split(path: str, expected: tuple) -> None:
    module = importlib.import_module("aiosmb.commons.utils.tschecker")

    assert module.tssplit(path) == expected


def test_universal_json_encoder_handles_supported_types() -> None:
    class State(enum.Enum):
        READY = "ready"

    class Record:
        def to_dict(self) -> dict:
            return {"kind": "record"}

    value = {
        "when": datetime.datetime(2024, 1, 2, 3, 4, 5),
        "state": State.READY,
        "address": ipaddress.ip_address("2001:db8::1"),
        "error": ValueError("sanitized"),
        "record": Record(),
    }

    assert json.loads(json.dumps(value, cls=UniversalEncoder)) == {
        "when": "2024-01-02T03:04:05",
        "state": "ready",
        "address": "2001:db8::1",
        "error": "sanitized",
        "record": {"kind": "record"},
    }


def test_cpassword_xml_parser_extracts_multiple_property_records() -> None:
    if sys.version_info < (3, 9):
        pytest.skip("blocked by KF-0107")
    from aiosmb.commons.utils.cpasswd import parse_cpasswd

    xml = """<?xml version="1.0" encoding="utf-8"?>
<Groups>
  <User name="first">
    <Properties userName="EXAMPLE\\alice" cpassword="ciphertext-one" />
  </User>
  <User name="second">
    <Properties cpassword="ciphertext-two" />
  </User>
</Groups>
"""

    assert parse_cpasswd("Groups.xml", xml) == [
        {
            "username": "EXAMPLE\\alice",
            "cpassword": "ciphertext-one",
            "filename": "Groups.xml",
            "xmltype": "Groups",
        },
        {
            "username": "",
            "cpassword": "ciphertext-two",
            "filename": "Groups.xml",
            "xmltype": "Groups",
        },
    ]


def test_cpassword_xml_parser_rejects_malformed_xml() -> None:
    if sys.version_info < (3, 9):
        pytest.skip("blocked by KF-0107")
    from aiosmb.commons.utils.cpasswd import parse_cpasswd

    with pytest.raises(ExpatError):
        parse_cpasswd("Groups.xml", "<Groups><User></Groups>")


def test_file_access_helpers_render_and_filter_basic_rights() -> None:
    access = FILE_ACCESS_MASK.FILE_READ_DATA | FILE_ACCESS_MASK.FILE_EXECUTE

    assert faccess_mask_to_unix(access) == "r-x"
    assert faccess_match(access, "rwx") == access
    assert faccess_match(access, "w") == FILE_ACCESS_MASK(0)


@pytest.mark.asyncio
async def test_result_decorators_preserve_success_and_capture_errors() -> None:
    async def succeeds():
        return "value", None

    async def fails():
        raise ValueError("boom")

    wrapped_success = red(succeeds)
    wrapped_failure = red(fails)

    assert await wrapped_success() == ("value", None)
    value, error = await wrapped_failure()
    assert value is None
    assert isinstance(error, ValueError)
    assert str(error) == "boom"
    assert await rr(succeeds()) == ("value", None)
    with pytest.raises(ValueError, match="boom"):
        await rr(fails())


@pytest.mark.asyncio
async def test_generator_result_decorators_stop_at_first_error() -> None:
    async def results():
        yield "first", None
        yield "second", ValueError("stop")
        yield "unreachable", None

    wrapped = red_gen(results)
    observed = [item async for item in wrapped()]

    assert observed[0] == ("first", None)
    assert observed[1][0] is None
    assert isinstance(observed[1][1], ValueError)

    raised = []
    with pytest.raises(ValueError, match="stop"):
        async for item in rr_gen(results()):
            raised.append(item)
    assert raised == [("first", None)]
