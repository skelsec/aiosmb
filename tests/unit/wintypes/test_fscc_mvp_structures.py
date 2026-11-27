"""Golden vectors for SMB 2.0.2 MVP FSCC structures."""

import struct

import pytest

from aiosmb.wintypes.fscc.FileAttributes import FileAttributes
from aiosmb.wintypes.fscc.structures.FileAllInformation import (
	FileAllInformation,
)
from aiosmb.wintypes.fscc.structures.FileBasicInformation import (
	FileBasicInformation,
)
from aiosmb.wintypes.fscc.structures.FileBothDirectoryInformation import (
	FileBothDirectoryInformation,
)
from aiosmb.wintypes.fscc.structures.FileDirectoryInformation import (
	FileDirectoryInformation,
)
from aiosmb.wintypes.fscc.structures.FileDispositionInformation import (
	FileDispositionInformation,
)
from aiosmb.wintypes.fscc.structures.FileEaInformation import FileEaInformation
from aiosmb.wintypes.fscc.structures.FileEndOfFileInformation import (
	FileEndOfFileInformation,
)
from aiosmb.wintypes.fscc.structures.FileFsAttributeInformation import (
	FileFsAttributeInformation,
	FileSystemAttributes,
)
from aiosmb.wintypes.fscc.structures.FileFsDeviceInformation import (
	DeviceCharacteristics,
	DeviceType,
	FileFsDeviceInformation,
)
from aiosmb.wintypes.fscc.structures.FileFsFullSizeInformation import (
	FileFsFullSizeInformation,
)
from aiosmb.wintypes.fscc.structures.FileFsSizeInformation import (
	FileFsSizeInformation,
)
from aiosmb.wintypes.fscc.structures.FileFsVolumeInformation import (
	FileFsVolumeInformation,
)
from aiosmb.wintypes.fscc.structures.FileFullDirectoryInformation import (
	FileFullDirectoryInformation,
	FileFullDirectoryInformationList,
)
from aiosmb.wintypes.fscc.structures.FileIdBothDirectoryInformation import (
	FileIdBothDirectoryInformation,
)
from aiosmb.wintypes.fscc.structures.FileIdFullDirectoryInformation import (
	FileIdFullDirectoryInformation,
)
from aiosmb.wintypes.fscc.structures.FileInternalInformation import (
	FileInternalInformation,
)
from aiosmb.wintypes.fscc.structures.FileNetworkOpenInformation import (
	FileNetworkOpenInformation,
)
from aiosmb.wintypes.fscc.structures.FileRenameInformation import (
	FileRenameInformation,
)
from aiosmb.wintypes.fscc.structures.FileStandardInformation import (
	FileStandardInformation,
)


pytestmark = pytest.mark.unit


def test_file_information_fixed_layouts_round_trip():
	basic_wire = struct.pack("<qqqqII", 1, 2, 3, -1, 0x20, 0)
	basic = FileBasicInformation.from_bytes(basic_wire)
	assert basic.ChangeTime == -1
	assert basic.FileAttributes is FileAttributes.FILE_ATTRIBUTE_ARCHIVE
	assert basic.to_bytes() == basic_wire

	standard_wire = struct.pack("<qqIBBH", 4096, 123, 2, 1, 0, 0)
	standard = FileStandardInformation.from_bytes(standard_wire)
	assert standard.DeletePending is True
	assert standard.Directory is False
	assert standard.to_bytes() == standard_wire

	internal_wire = struct.pack("<q", 0x102030405)
	internal = FileInternalInformation.from_bytes(internal_wire)
	assert internal.IndexNumber == 0x102030405
	assert internal.to_bytes() == internal_wire

	ea_wire = struct.pack("<I", 17)
	assert FileEaInformation.from_bytes(ea_wire).to_bytes() == ea_wire

	network_wire = struct.pack(
		"<qqqqqqII", 1, 2, 3, 4, 8192, 7, 0x20, 0
	)
	network = FileNetworkOpenInformation.from_bytes(network_wire)
	assert network.EndOfFile == 7
	assert network.to_bytes() == network_wire


def test_file_all_information_composes_spec_order():
	name = "all.txt".encode("utf-16-le")
	wire = (
		struct.pack("<qqqqII", 1, 2, 3, 4, 0x20, 0)
		+ struct.pack("<qqIBBH", 4096, 12, 1, 0, 0, 0)
		+ struct.pack("<q", 77)
		+ struct.pack("<I", 5)
		+ struct.pack("<I", 0x120089)
		+ struct.pack("<q", 9)
		+ struct.pack("<I", 2)
		+ struct.pack("<I", 0)
		+ struct.pack("<I", len(name))
		+ name
	)

	info = FileAllInformation.from_bytes(wire)

	assert len(wire) == 100 + len(name)
	assert info.StandardInformation.EndOfFile == 12
	assert info.InternalInformation.IndexNumber == 77
	assert info.NameInformation.FileName == "all.txt"
	assert info.to_bytes() == wire


def test_filesystem_information_variable_and_fixed_layouts():
	label = "DATA".encode("utf-16-le")
	volume_wire = struct.pack("<qIIBB", 123, 0xAABBCCDD, len(label), 1, 0) + label
	volume = FileFsVolumeInformation.from_bytes(volume_wire)
	assert volume.VolumeLabel == "DATA"
	assert volume.SupportsObjects is True
	assert volume.to_bytes() == volume_wire

	size_wire = struct.pack("<qqII", 1000, 400, 8, 512)
	assert FileFsSizeInformation.from_bytes(size_wire).to_bytes() == size_wire

	full_size_wire = struct.pack("<qqqII", 1000, 350, 400, 8, 512)
	full_size = FileFsFullSizeInformation.from_bytes(full_size_wire)
	assert full_size.CallerAvailableAllocationUnits == 350
	assert full_size.to_bytes() == full_size_wire

	device_wire = struct.pack(
		"<II",
		DeviceType.FILE_DEVICE_DISK_FILE_SYSTEM.value,
		DeviceCharacteristics.FILE_DEVICE_IS_MOUNTED.value,
	)
	device = FileFsDeviceInformation.from_bytes(device_wire)
	assert device.DeviceType is DeviceType.FILE_DEVICE_DISK_FILE_SYSTEM
	assert device.to_bytes() == device_wire

	fs_name = "NTFS".encode("utf-16-le")
	attributes = (
		FileSystemAttributes.FILE_CASE_PRESERVED_NAMES
		| FileSystemAttributes.FILE_UNICODE_ON_DISK
	)
	attribute_wire = struct.pack(
		"<III", attributes.value, 255, len(fs_name)
	) + fs_name
	attribute = FileFsAttributeInformation.from_bytes(attribute_wire)
	assert attribute.FileSystemName == "NTFS"
	assert attribute.FileSystemAttributes == attributes
	assert attribute.to_bytes() == attribute_wire


def test_set_information_payload_layouts():
	eof_wire = struct.pack("<q", 123456)
	assert FileEndOfFileInformation.from_bytes(eof_wire).to_bytes() == eof_wire

	disposition = FileDispositionInformation.from_bytes(b"\x01")
	assert disposition.DeletePending is True
	assert disposition.DeleteFile is True
	assert disposition.to_bytes() == b"\x01"

	name = r"\renamed.txt".encode("utf-16-le")
	rename_wire = (
		struct.pack("<B7sQI", 1, b"\x00" * 7, 0, len(name)) + name
	)
	rename = FileRenameInformation.from_bytes(rename_wire)
	assert rename.ReplaceIfExists is True
	assert rename.FileName == r"\renamed.txt"
	assert rename.to_bytes() == rename_wire


def _directory_entry(entry_type, name="a.txt"):
	entry = entry_type()
	entry.FileIndex = 7
	entry.CreationTime = 1
	entry.LastAccessTime = 2
	entry.LastWriteTime = 3
	entry.ChangeTime = 4
	entry.EndOfFile = 5
	entry.AllocationSize = 4096
	entry.FileAttributes = FileAttributes.FILE_ATTRIBUTE_ARCHIVE
	entry.FileName = name
	if hasattr(entry, "EaSize"):
		entry.EaSize = 6
	if hasattr(entry, "ShortName"):
		entry.ShortName = "A.TXT"
	if hasattr(entry, "FileId"):
		entry.FileId = 0x1122334455667788
	return entry


@pytest.mark.parametrize(
	"entry_type,fixed_size",
	(
		(FileDirectoryInformation, 64),
		(FileFullDirectoryInformation, 68),
		(FileBothDirectoryInformation, 94),
		(FileIdFullDirectoryInformation, 76),
		(FileIdBothDirectoryInformation, 104),
	),
)
def test_directory_record_classes_use_spec_filename_offsets(
	entry_type, fixed_size
):
	entry = _directory_entry(entry_type)

	wire = entry.to_bytes()
	parsed = entry_type.from_bytes(wire)

	assert len(wire) == fixed_size + len("a.txt".encode("utf-16-le"))
	assert wire[fixed_size:] == "a.txt".encode("utf-16-le")
	assert parsed.FileName == "a.txt"
	assert parsed.to_bytes() == wire


def test_directory_list_serializer_aligns_relative_next_offsets():
	first = _directory_entry(FileFullDirectoryInformation, "one")
	second = _directory_entry(FileFullDirectoryInformation, "β.txt")

	wire = FileFullDirectoryInformationList.to_bytes([first, second])
	parsed = FileFullDirectoryInformationList.from_bytes(wire)

	assert int.from_bytes(wire[0:4], "little") == 80
	assert int.from_bytes(wire[80:84], "little") == 0
	assert wire[74:80] == b"\x00" * 6
	assert [entry.FileName for entry in parsed] == ["one", "β.txt"]
