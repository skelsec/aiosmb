import datetime
import enum
import io


WINDOWS_EPOCH = 116444736000000000


def read_exact(buff, size, field='structure'):
	data = buff.read(size)
	if len(data) != size:
		raise ValueError('Truncated %s' % field)
	return data


def as_int(value):
	if isinstance(value, enum.Enum):
		return value.value
	return value


def filetime_value(value):
	if hasattr(value, 'dwLowDateTime') and hasattr(value, 'dwHighDateTime'):
		return (value.dwHighDateTime << 32) | value.dwLowDateTime
	if isinstance(value, datetime.datetime):
		if value.tzinfo is not None:
			epoch = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
			seconds = (value.astimezone(datetime.timezone.utc) - epoch).total_seconds()
		else:
			epoch = datetime.datetime(1970, 1, 1)
			seconds = (value - epoch).total_seconds()
		return int(seconds * 10000000) + WINDOWS_EPOCH
	return value


def encode_utf16(value, field):
	if value is None:
		return b''
	if not isinstance(value, str):
		raise TypeError('%s must be str' % field)
	return value.encode('utf-16-le')


def decode_utf16(data, field):
	if len(data) % 2:
		raise ValueError('%s has an odd UTF-16 byte length' % field)
	try:
		return data.decode('utf-16-le')
	except UnicodeDecodeError as exc:
		raise ValueError('Invalid UTF-16 in %s' % field) from exc


def from_bytes(cls, data):
	if not isinstance(data, (bytes, bytearray, memoryview)):
		raise TypeError('%s data must be bytes-like' % cls.__name__)
	return cls.from_buffer(io.BytesIO(bytes(data)))
