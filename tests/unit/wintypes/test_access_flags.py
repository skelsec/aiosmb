"""Exact-value and composition tests for Windows flag definitions."""

import pytest

from aiosmb.wintypes.access_mask import DirectoryAccessMask, FileAccessMask
from aiosmb.wintypes.dtyp.constrcuted_security.access_mask import ACCESS_MASK
from aiosmb.wintypes.dtyp.constrcuted_security.ace import (
    ADS_ACCESS_MASK,
    ACCESS_ALLOWED_OBJECT_Flags,
    AceFlags,
)
from aiosmb.wintypes.dtyp.constrcuted_security.security_descriptor import SE_SACL
from aiosmb.wintypes.dtyp.constrcuted_security.security_information import (
    SECURITY_INFORMATION,
)
from aiosmb.wintypes.fscc.FileAttributes import FileAttributes
from aiosmb.wintypes.fscc.structures.fileinfoclass import FileInfoClass


pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "flag,expected",
    [
        (FileAccessMask.FILE_READ_DATA, 0x00000001),
        (FileAccessMask.FILE_APPEND_DATA, 0x00000004),
        (FileAccessMask.FILE_DELETE_CHILD, 0x00000040),
        (FileAccessMask.READ_CONTROL, 0x00020000),
        (FileAccessMask.ACCESS_SYSTEM_SECURITY, 0x01000000),
        (FileAccessMask.GENERIC_WRITE, 0x40000000),
        (FileAccessMask.GENERIC_READ, 0x80000000),
        (DirectoryAccessMask.FILE_LIST_DIRECTORY, 0x00000001),
        (DirectoryAccessMask.FILE_ADD_SUBDIRECTORY, 0x00000004),
        (DirectoryAccessMask.FILE_TRAVERSE, 0x00000020),
        (DirectoryAccessMask.GENERIC_ALL, 0x10000000),
    ],
)
def test_file_and_directory_access_mask_values(flag, expected):
    assert int(flag) == expected


def test_access_mask_composition_and_membership():
    desired = (
        FileAccessMask.FILE_READ_DATA
        | FileAccessMask.FILE_READ_ATTRIBUTES
        | FileAccessMask.READ_CONTROL
    )

    assert int(desired) == 0x00020081
    assert desired & FileAccessMask.FILE_READ_DATA
    assert desired & FileAccessMask.READ_CONTROL
    assert not desired & FileAccessMask.FILE_WRITE_DATA
    assert FileAccessMask(0x00000200).value == 0x00000200


@pytest.mark.xfail(
    strict=True,
    reason="KF-0302: DTYP ACCESS_MASK.GENERIC_WRITE has the wrong bit value",
)
def test_dtyp_generic_write_uses_standard_high_bit():
    assert ACCESS_MASK.GENERIC_WRITE.value == 0x40000000


@pytest.mark.parametrize(
    "flag,expected",
    [
        (ADS_ACCESS_MASK.CREATE_CHILD, 0x00000001),
        (ADS_ACCESS_MASK.CONTROL_ACCESS, 0x00000100),
        (ADS_ACCESS_MASK.WRITE_DACL, 0x00040000),
        (ADS_ACCESS_MASK.GENERIC_READ, 0x80000000),
        (AceFlags.OBJECT_INHERIT_ACE, 0x01),
        (AceFlags.CONTAINER_INHERIT_ACE, 0x02),
        (AceFlags.INHERITED_ACE, 0x10),
        (AceFlags.SUCCESSFUL_ACCESS_ACE_FLAG, 0x40),
        (AceFlags.FAILED_ACCESS_ACE_FLAG, 0x80),
    ],
)
def test_ace_access_and_header_flag_values(flag, expected):
    assert int(flag) == expected


def test_object_ace_presence_flags_compose():
    both = (
        ACCESS_ALLOWED_OBJECT_Flags.ACE_OBJECT_TYPE_PRESENT
        | ACCESS_ALLOWED_OBJECT_Flags.ACE_INHERITED_OBJECT_TYPE_PRESENT
    )

    assert both.value == 3
    assert both & ACCESS_ALLOWED_OBJECT_Flags.ACE_OBJECT_TYPE_PRESENT
    assert both & ACCESS_ALLOWED_OBJECT_Flags.ACE_INHERITED_OBJECT_TYPE_PRESENT
    assert ACCESS_ALLOWED_OBJECT_Flags.NONE.value == 0


@pytest.mark.parametrize(
    "flag,expected",
    [
        (SECURITY_INFORMATION.OWNER, 0x00000001),
        (SECURITY_INFORMATION.DACL, 0x00000004),
        (SECURITY_INFORMATION.BACKUP, 0x00010000),
        (SECURITY_INFORMATION.UNPROTECTED_DACL, 0x20000000),
        (SECURITY_INFORMATION.PROTECTED_DACL, 0x80000000),
        (SE_SACL.SE_DACL_PRESENT, 0x0004),
        (SE_SACL.SE_SACL_PRESENT, 0x0010),
        (SE_SACL.SE_DACL_PROTECTED, 0x1000),
        (SE_SACL.SE_SACL_PROTECTED, 0x2000),
        (SE_SACL.SE_SELF_RELATIVE, 0x8000),
    ],
)
def test_security_information_and_control_values(flag, expected):
    assert int(flag) == expected


def test_security_flag_composition():
    requested = (
        SECURITY_INFORMATION.OWNER
        | SECURITY_INFORMATION.GROUP
        | SECURITY_INFORMATION.DACL
    )
    control = SE_SACL.SE_SELF_RELATIVE | SE_SACL.SE_DACL_PRESENT

    assert requested.value == 0x00000007
    assert control.value == 0x8004


@pytest.mark.xfail(
    strict=True,
    reason="KF-0312: SE_SACL_DEFAULTED duplicates the DACL defaulted bit",
)
def test_sacl_defaulted_uses_its_distinct_control_bit():
    assert SE_SACL.SE_SACL_DEFAULTED.value == 0x0020


@pytest.mark.parametrize(
    "flag,expected",
    [
        (FileAttributes.FILE_ATTRIBUTE_READONLY, 0x00000001),
        (FileAttributes.FILE_ATTRIBUTE_DIRECTORY, 0x00000010),
        (FileAttributes.FILE_ATTRIBUTE_ARCHIVE, 0x00000020),
        (FileAttributes.FILE_ATTRIBUTE_REPARSE_POINT, 0x00000400),
        (FileAttributes.FILE_ATTRIBUTE_ENCRYPTED, 0x00004000),
        (FileAttributes.FILE_ATTRIBUTE_NO_SCRUB_DATA, 0x00020000),
    ],
)
def test_file_attribute_values(flag, expected):
    assert int(flag) == expected


def test_file_attributes_preserve_combinations_and_unknown_bits():
    attrs = (
        FileAttributes.FILE_ATTRIBUTE_DIRECTORY
        | FileAttributes.FILE_ATTRIBUTE_HIDDEN
        | FileAttributes(0x00040000)
    )

    assert attrs.value == 0x00040012
    assert attrs & FileAttributes.FILE_ATTRIBUTE_DIRECTORY
    assert attrs & FileAttributes.FILE_ATTRIBUTE_HIDDEN


@pytest.mark.parametrize(
    "info_class,expected",
    [
        (FileInfoClass.FileDirectoryInformation, 1),
        (FileInfoClass.FileFullDirectoryInformation, 2),
        (FileInfoClass.FileBothDirectoryInformation, 3),
        (FileInfoClass.FileBasicInformation, 4),
        (FileInfoClass.FileNamesInformation, 12),
        (FileInfoClass.FileIdBothDirectoryInformation, 37),
        (FileInfoClass.FileStandardLinkInformation, 54),
    ],
)
def test_file_information_class_values(info_class, expected):
    assert info_class.value == expected
    assert FileInfoClass(expected) is info_class


def test_file_information_class_rejects_unknown_value():
    with pytest.raises(ValueError):
        FileInfoClass(0xFF)
