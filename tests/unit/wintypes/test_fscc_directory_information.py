"""Golden vectors for FSCC full-directory information records."""

import datetime
import io
import struct

import pytest

from aiosmb.wintypes.fscc.FileAttributes import FileAttributes
from aiosmb.wintypes.fscc.structures.FileFullDirectoryInformation import (
    FileFullDirectoryInformation,
    FileFullDirectoryInformationList,
)


pytestmark = pytest.mark.unit

WINDOWS_UNIX_EPOCH = 116444736000000000
WINDOWS_2020_EPOCH = 132223104000000000


def _record(
    name,
    next_offset=0,
    file_index=7,
    end_of_file=12345,
    allocation_size=16384,
    attributes=None,
    ea_size=0,
    declared_name_length=None,
):
    if attributes is None:
        attributes = (
            FileAttributes.FILE_ATTRIBUTE_ARCHIVE
            | FileAttributes.FILE_ATTRIBUTE_READONLY
        )
    encoded_name = name.encode("utf-16-le")
    if declared_name_length is None:
        declared_name_length = len(encoded_name)
    fixed = struct.pack(
        "<LLQQQQqqLLL",
        next_offset,
        file_index,
        WINDOWS_UNIX_EPOCH,
        WINDOWS_2020_EPOCH,
        0xFFFFFFFFFFFFFFFF,
        0,
        end_of_file,
        allocation_size,
        attributes.value,
        declared_name_length,
        ea_size,
    )
    return fixed + encoded_name


def test_full_directory_information_parses_golden_record():
    raw = _record("report.txt")
    buff = io.BytesIO(raw + b"tail")

    info = FileFullDirectoryInformation.from_buffer(buff)

    assert info.NextEntryOffset == 0
    assert info.FileIndex == 7
    assert info.CreationTime == datetime.datetime(1970, 1, 1)
    assert info.LastAccessTime == datetime.datetime(2020, 1, 1)
    assert info.LastWriteTime == datetime.datetime(3000, 1, 1)
    assert info.ChangeTime == datetime.datetime(1970, 1, 1)
    assert info.EndOfFile == 12345
    assert info.AllocationSize == 16384
    assert info.FileAttributes == (
        FileAttributes.FILE_ATTRIBUTE_ARCHIVE
        | FileAttributes.FILE_ATTRIBUTE_READONLY
    )
    assert info.FileNameLength == len("report.txt".encode("utf-16-le"))
    assert info.EaSize == 0
    assert info.FileName == "report.txt"
    assert "FileName : report.txt" in str(info)
    assert buff.read() == b"tail"


def test_full_directory_information_preserves_signed_sizes_and_unicode():
    raw = _record(
        "δοκιμή.txt",
        file_index=0xFFFFFFFF,
        end_of_file=-1,
        allocation_size=-2,
        attributes=FileAttributes.FILE_ATTRIBUTE_DIRECTORY,
        ea_size=9,
    )

    info = FileFullDirectoryInformation.from_bytes(raw)

    assert info.FileIndex == 0xFFFFFFFF
    assert info.EndOfFile == -1
    assert info.AllocationSize == -2
    assert info.FileAttributes is FileAttributes.FILE_ATTRIBUTE_DIRECTORY
    assert info.EaSize == 9
    assert info.FileName == "δοκιμή.txt"


def test_directory_information_list_follows_aligned_offsets():
    first = _record("one", next_offset=80, file_index=1)
    assert len(first) == 74
    first += b"\x00" * (80 - len(first))
    second = _record(
        "β.txt",
        file_index=2,
        attributes=(
            FileAttributes.FILE_ATTRIBUTE_HIDDEN
            | FileAttributes.FILE_ATTRIBUTE_ARCHIVE
        ),
    )

    entries = FileFullDirectoryInformationList.from_bytes(first + second)

    assert [entry.FileName for entry in entries] == ["one", "β.txt"]
    assert [entry.FileIndex for entry in entries] == [1, 2]
    assert entries[0].NextEntryOffset == 80
    assert entries[1].NextEntryOffset == 0
    assert entries[1].FileAttributes == (
        FileAttributes.FILE_ATTRIBUTE_HIDDEN
        | FileAttributes.FILE_ATTRIBUTE_ARCHIVE
    )


def test_directory_information_list_offsets_use_initial_buffer_position():
    first = _record("one", next_offset=80, file_index=1)
    first += b"\x00" * (80 - len(first))
    second = _record("two", file_index=2)
    buff = io.BytesIO(b"prefix" + first + second)
    buff.seek(len(b"prefix"))

    entries = FileFullDirectoryInformationList.from_buffer(buff)

    assert [entry.FileName for entry in entries] == ["one", "two"]


def test_directory_information_rejects_odd_utf16_name_length():
    raw = _record("A", declared_name_length=1)

    with pytest.raises(UnicodeDecodeError):
        FileFullDirectoryInformation.from_bytes(raw)


@pytest.mark.xfail(
    strict=True,
    reason="KF-0310: FSCC parser accepts a truncated declared file name",
)
def test_directory_information_rejects_truncated_file_name():
    raw = _record("AB", declared_name_length=8)

    with pytest.raises(Exception):
        FileFullDirectoryInformation.from_bytes(raw)


@pytest.mark.xfail(
    strict=True,
    reason="KF-0314: directory list parser follows offsets beyond the buffer",
)
def test_directory_information_list_rejects_out_of_bounds_next_offset():
    raw = _record("one", next_offset=256)

    with pytest.raises(Exception):
        FileFullDirectoryInformationList.from_bytes(raw)
