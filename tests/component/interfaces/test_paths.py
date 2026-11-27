"""Path construction contracts for the high-level SMB interfaces."""

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

if sys.version_info < (3, 9):
    pytest.skip("blocked by KF-0107", allow_module_level=True)

from aiosmb.commons.interfaces.directory import SMBDirectory
from aiosmb.commons.interfaces.file import SMBFile
from aiosmb.commons.interfaces.share import SMBShare


pytestmark = pytest.mark.component


@pytest.mark.parametrize("interface_type", [SMBFile, SMBDirectory])
def test_unc_path_preserves_share_and_splits_vss_suffix(interface_type):
    unc_path = (
        r"\\fileserver.example\C$\reports\annual.txt"
        "@GMT-2024.01.02-03.04.05"
    )

    entry = interface_type.from_uncpath(unc_path)

    assert entry.share_path == r"\\fileserver.example\C$"
    assert entry.fullpath == r"reports\annual.txt"
    assert entry.name == "annual.txt"
    assert entry.vstimestamp == "@GMT-2024.01.02-03.04.05"
    assert entry.unc_path == unc_path


@pytest.mark.parametrize("interface_type", [SMBFile, SMBDirectory])
def test_remote_path_accepts_leading_and_unprefixed_share(interface_type):
    connection = SimpleNamespace(
        target=SimpleNamespace(get_hostname_or_ip=lambda: "server.invalid")
    )

    prefixed = interface_type.from_remotepath(
        connection, r"\C$\folder\entry.txt"
    )
    unprefixed = interface_type.from_remotepath(
        connection, r"C$\folder\entry.txt"
    )

    assert prefixed.unc_path == r"\\server.invalid\C$\folder\entry.txt"
    assert unprefixed.unc_path == prefixed.unc_path
    assert prefixed.fullpath == r"folder\entry.txt"
    assert unprefixed.fullpath == prefixed.fullpath


def test_file_target_path_normalizes_missing_leading_separator():
    target = SimpleNamespace(
        path="C$/folder/report.txt",
        get_hostname_or_ip=lambda: "server.invalid",
    )

    smb_file = SMBFile.from_smbtarget(target)

    assert smb_file.unc_path == r"\\server.invalid\C$\folder\report.txt"
    assert smb_file.share_path == r"\\server.invalid\C$"
    assert smb_file.fullpath == r"folder\report.txt"


@pytest.mark.xfail(
    strict=True,
    reason=(
        "KF-0614: directory target paths omit the server/share separator "
        "when the target path is unprefixed"
    ),
)
def test_directory_target_path_normalizes_missing_leading_separator():
    target = SimpleNamespace(
        path="C$/folder",
        get_hostname_or_ip=lambda: "server.invalid",
    )

    directory = SMBDirectory.from_smbtarget(target)

    assert directory.unc_path == r"\\server.invalid\C$\folder"
    assert directory.share_path == r"\\server.invalid\C$"
    assert directory.fullpath == "folder"


@pytest.mark.parametrize("interface_type", [SMBFile, SMBDirectory])
def test_vss_copy_builds_a_distinct_timestamped_entry(interface_type):
    original = interface_type.from_uncpath(
        r"\\server.invalid\C$\folder\entry.txt"
    )

    copy = original.get_vscopy("@GMT-2023.12.31-23.59.58")

    assert copy is not original
    assert copy.name == original.name
    assert copy.fullpath == original.fullpath
    assert copy.vstimestamp == "@GMT-2023.12.31-23.59.58"
    assert copy.unc_path == (
        original.unc_path + "@GMT-2023.12.31-23.59.58"
    )


def test_file_mirror_path_sanitizes_host_and_admin_share(tmp_path):
    result = SMBFile.prepare_mirror_path(
        str(tmp_path),
        r"\\host.example\C$\one\two\report.txt",
    )

    assert result == (
        Path(str(tmp_path))
        .joinpath("host_example", "C_", "one", "two")
        .resolve()
    )


def test_directory_join_and_child_path_views_are_windows_paths():
    directory = SMBDirectory.from_uncpath(r"\\server.invalid\data\root")
    child_dir = SMBDirectory.from_uncpath(
        r"\\server.invalid\data\root\child"
    )
    child_file = SMBFile.from_uncpath(
        r"\\server.invalid\data\root\report.txt"
    )
    directory.subdirs[child_dir.name] = child_dir
    directory.files[child_file.name] = child_file

    assert directory / "next" == r"\\server.invalid\data\root\next"
    assert directory // r"\next" == r"\\server.invalid\data\root\next"
    assert directory.get_subdir_paths() == [r"root\child"]
    assert directory.get_subdir_paths(fullpath=True) == [
        r"\\server.invalid\data\root\child"
    ]
    assert directory.get_file_paths() == [r"root\report.txt"]
    assert directory.get_file_paths(fullpath=True) == [
        r"\\server.invalid\data\root\report.txt"
    ]


def test_share_from_unc_preserves_path_and_normalizes_remark():
    share = SMBShare(
        name="data",
        stype=0,
        remark="team share\x00",
        fullpath=r"\\server.invalid\data",
    )
    parsed = SMBShare.from_unc(r"\\server.invalid\archive")

    assert share.name == "data"
    assert share.remark == "team share"
    assert share.fullpath == r"\\server.invalid\data"
    assert share.unc_path == share.fullpath
    assert parsed.fullpath == r"\\server.invalid\archive"
    assert parsed.unc_path == parsed.fullpath
