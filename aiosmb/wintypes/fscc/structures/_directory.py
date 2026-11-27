import datetime
import io

from aiosmb.wintypes.dtyp.structures.filetime import FILETIME
from aiosmb.wintypes.fscc.FileAttributes import FileAttributes
from aiosmb.wintypes.fscc.structures._helpers import (
	as_int,
	encode_utf16,
	filetime_value,
)


def _directory_time(value):
	# Preserve the sentinel conventions used by the existing FILETIME parser.
	if isinstance(value, datetime.datetime):
		if value == datetime.datetime(1970, 1, 1):
			return 0
		if value == datetime.datetime(3000, 1, 1):
			return 0xFFFFFFFFFFFFFFFF
	return filetime_value(value)


def _read_directory_time(buff, msg, field):
	raw = buff.read(8)
	value = FILETIME.from_bytes(raw).datetime
	setattr(msg, field, value)
	setattr(msg, '_' + field + 'Raw', int.from_bytes(raw, 'little'))
	setattr(msg, '_' + field + 'Parsed', value)


def _write_directory_time(msg, field):
	value = getattr(msg, field)
	if (
		hasattr(msg, '_' + field + 'Raw')
		and value == getattr(msg, '_' + field + 'Parsed')
	):
		return getattr(msg, '_' + field + 'Raw')
	return _directory_time(value)


def _read_common(buff, msg):
	msg.NextEntryOffset = int.from_bytes(buff.read(4), 'little')
	msg.FileIndex = int.from_bytes(buff.read(4), 'little')
	_read_directory_time(buff, msg, 'CreationTime')
	_read_directory_time(buff, msg, 'LastAccessTime')
	_read_directory_time(buff, msg, 'LastWriteTime')
	_read_directory_time(buff, msg, 'ChangeTime')
	msg.EndOfFile = int.from_bytes(buff.read(8), 'little', signed=True)
	msg.AllocationSize = int.from_bytes(buff.read(8), 'little', signed=True)
	msg.FileAttributes = FileAttributes(
		int.from_bytes(buff.read(4), 'little')
	)
	msg.FileNameLength = int.from_bytes(buff.read(4), 'little')


def _write_common(msg):
	t  = (msg.NextEntryOffset or 0).to_bytes(4, 'little')
	t += (msg.FileIndex or 0).to_bytes(4, 'little')
	for field in (
		'CreationTime',
		'LastAccessTime',
		'LastWriteTime',
		'ChangeTime',
	):
		t += _write_directory_time(msg, field).to_bytes(
			8, 'little', signed=False
		)
	t += (msg.EndOfFile or 0).to_bytes(8, 'little', signed=True)
	t += (msg.AllocationSize or 0).to_bytes(8, 'little', signed=True)
	t += as_int(msg.FileAttributes).to_bytes(4, 'little')
	return t


class _DirectoryInformationBase:
	def __init__(self):
		self.NextEntryOffset = 0
		self.FileIndex = 0
		self.CreationTime = 0
		self.LastAccessTime = 0
		self.LastWriteTime = 0
		self.ChangeTime = 0
		self.EndOfFile = 0
		self.AllocationSize = 0
		self.FileAttributes = FileAttributes(0)
		self.FileNameLength = 0
		self.FileName = ''

	def _name_bytes(self):
		name = encode_utf16(self.FileName, 'FileName')
		self.FileNameLength = len(name)
		return name

	def __str__(self):
		t = '===== %s =====\r\n' % self.__class__.__name__
		for key, value in self.__dict__.items():
			if key.startswith('_'):
				continue
			t += '%s : %s\r\n' % (key, value)
		return t


class FileDirectoryInformation(_DirectoryInformationBase):
	def to_bytes(self):
		name = self._name_bytes()
		return (
			_write_common(self)
			+ self.FileNameLength.to_bytes(4, 'little')
			+ name
		)

	@staticmethod
	def from_bytes(data):
		return FileDirectoryInformation.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		msg = FileDirectoryInformation()
		_read_common(buff, msg)
		msg.FileName = buff.read(msg.FileNameLength).decode('utf-16-le')
		return msg


class FileFullDirectoryInformation(_DirectoryInformationBase):
	def __init__(self):
		super().__init__()
		self.EaSize = 0

	def to_bytes(self):
		name = self._name_bytes()
		return (
			_write_common(self)
			+ self.FileNameLength.to_bytes(4, 'little')
			+ self.EaSize.to_bytes(4, 'little')
			+ name
		)

	@staticmethod
	def from_bytes(data):
		return FileFullDirectoryInformation.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		msg = FileFullDirectoryInformation()
		_read_common(buff, msg)
		msg.EaSize = int.from_bytes(buff.read(4), 'little')
		msg.FileName = buff.read(msg.FileNameLength).decode('utf-16-le')
		return msg


class FileBothDirectoryInformation(FileFullDirectoryInformation):
	def __init__(self):
		super().__init__()
		self.ShortNameLength = 0
		self.Reserved = 0
		self.ShortName = ''

	def to_bytes(self):
		name = self._name_bytes()
		short_name = encode_utf16(self.ShortName, 'ShortName')
		if len(short_name) > 24:
			raise ValueError('ShortName exceeds 12 UTF-16 code units')
		self.ShortNameLength = len(short_name)
		return (
			_write_common(self)
			+ self.FileNameLength.to_bytes(4, 'little')
			+ self.EaSize.to_bytes(4, 'little')
			+ self.ShortNameLength.to_bytes(1, 'little')
			+ self.Reserved.to_bytes(1, 'little')
			+ short_name.ljust(24, b'\x00')
			+ name
		)

	@staticmethod
	def from_bytes(data):
		return FileBothDirectoryInformation.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		msg = FileBothDirectoryInformation()
		_read_common(buff, msg)
		msg.EaSize = int.from_bytes(buff.read(4), 'little')
		msg.ShortNameLength = int.from_bytes(buff.read(1), 'little')
		msg.Reserved = int.from_bytes(buff.read(1), 'little')
		short_name = buff.read(24)[:msg.ShortNameLength]
		msg.ShortName = short_name.decode('utf-16-le')
		msg.FileName = buff.read(msg.FileNameLength).decode('utf-16-le')
		return msg


class FileIdFullDirectoryInformation(FileFullDirectoryInformation):
	def __init__(self):
		super().__init__()
		self.FileId = 0

	def to_bytes(self):
		name = self._name_bytes()
		return (
			_write_common(self)
			+ self.FileNameLength.to_bytes(4, 'little')
			+ self.EaSize.to_bytes(4, 'little')
			+ self.FileId.to_bytes(8, 'little')
			+ name
		)

	@staticmethod
	def from_bytes(data):
		return FileIdFullDirectoryInformation.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		msg = FileIdFullDirectoryInformation()
		_read_common(buff, msg)
		msg.EaSize = int.from_bytes(buff.read(4), 'little')
		msg.FileId = int.from_bytes(buff.read(8), 'little')
		msg.FileName = buff.read(msg.FileNameLength).decode('utf-16-le')
		return msg


class FileIdBothDirectoryInformation(FileBothDirectoryInformation):
	def __init__(self):
		super().__init__()
		self.Reserved2 = 0
		self.FileId = 0

	def to_bytes(self):
		name = self._name_bytes()
		short_name = encode_utf16(self.ShortName, 'ShortName')
		if len(short_name) > 24:
			raise ValueError('ShortName exceeds 12 UTF-16 code units')
		self.ShortNameLength = len(short_name)
		return (
			_write_common(self)
			+ self.FileNameLength.to_bytes(4, 'little')
			+ self.EaSize.to_bytes(4, 'little')
			+ self.ShortNameLength.to_bytes(1, 'little')
			+ self.Reserved.to_bytes(1, 'little')
			+ short_name.ljust(24, b'\x00')
			+ self.Reserved2.to_bytes(2, 'little')
			+ self.FileId.to_bytes(8, 'little')
			+ name
		)

	@staticmethod
	def from_bytes(data):
		return FileIdBothDirectoryInformation.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		msg = FileIdBothDirectoryInformation()
		_read_common(buff, msg)
		msg.EaSize = int.from_bytes(buff.read(4), 'little')
		msg.ShortNameLength = int.from_bytes(buff.read(1), 'little')
		msg.Reserved = int.from_bytes(buff.read(1), 'little')
		short_name = buff.read(24)[:msg.ShortNameLength]
		msg.ShortName = short_name.decode('utf-16-le')
		msg.Reserved2 = int.from_bytes(buff.read(2), 'little')
		msg.FileId = int.from_bytes(buff.read(8), 'little')
		msg.FileName = buff.read(msg.FileNameLength).decode('utf-16-le')
		return msg


def serialize_directory_information(entries):
	entries = list(entries)
	result = bytearray()
	for index, entry in enumerate(entries):
		entry.NextEntryOffset = 0
		record = entry.to_bytes()
		if index != len(entries) - 1:
			next_offset = (len(record) + 7) & ~7
			entry.NextEntryOffset = next_offset
			record = entry.to_bytes()
			record += b'\x00' * (next_offset - len(record))
		result.extend(record)
	return bytes(result)


class _DirectoryInformationList:
	ENTRY_TYPE = None

	@classmethod
	def from_bytes(cls, data):
		return cls.from_buffer(io.BytesIO(data))

	@classmethod
	def from_buffer(cls, buff):
		start = buff.tell()
		entries = []
		info = cls.ENTRY_TYPE.from_buffer(buff)
		entries.append(info)
		while info.NextEntryOffset != 0:
			buff.seek(start + info.NextEntryOffset, io.SEEK_SET)
			start = buff.tell()
			info = cls.ENTRY_TYPE.from_buffer(buff)
			entries.append(info)
		return entries

	@staticmethod
	def to_bytes(entries):
		return serialize_directory_information(entries)


class FileDirectoryInformationList(_DirectoryInformationList):
	ENTRY_TYPE = FileDirectoryInformation


class FileFullDirectoryInformationList(_DirectoryInformationList):
	ENTRY_TYPE = FileFullDirectoryInformation


class FileBothDirectoryInformationList(_DirectoryInformationList):
	ENTRY_TYPE = FileBothDirectoryInformation


class FileIdFullDirectoryInformationList(_DirectoryInformationList):
	ENTRY_TYPE = FileIdFullDirectoryInformation


class FileIdBothDirectoryInformationList(_DirectoryInformationList):
	ENTRY_TYPE = FileIdBothDirectoryInformation
