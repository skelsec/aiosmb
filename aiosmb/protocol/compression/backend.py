"""Optional native codecs for SMB 3.1.1 transport compression."""

import importlib
from typing import Tuple

from aiosmb import logger
from aiosmb.protocol.smb2.commands.negotiate import SMB2CompressionType


class SMBCompressionUnavailable(RuntimeError):
	"""Raised when transport compression was requested without its native extra."""


_NATIVE_UNSET = object()
_native = _NATIVE_UNSET
_unavailable_warning_emitted = False
_CODECS = (
	(SMB2CompressionType.LZ77, 'compress_lz77', 'decompress_lz77'),
	(
		SMB2CompressionType.LZ77_Huffman,
		'compress_lz77_huffman',
		'decompress_lz77_huffman',
	),
	(SMB2CompressionType.LZ4, 'compress_lz4', 'decompress_lz4'),
	(SMB2CompressionType.LZNT1, 'compress_lznt1', 'decompress_lznt1'),
)


def _load_native():
	global _native
	if _native is _NATIVE_UNSET:
		try:
			_native = importlib.import_module('aiosmb_compression')
		except ImportError:
			_native = None
	return _native


def is_available() -> bool:
	return bool(supported_algorithms())


def supported_algorithms() -> Tuple[SMB2CompressionType, ...]:
	native = _load_native()
	if native is None:
		return ()
	return tuple(
		algorithm
		for algorithm, compressor_name, decompressor_name in _CODECS
		if (
			callable(getattr(native, compressor_name, None)) and
			callable(getattr(native, decompressor_name, None))
		)
	)


def warn_if_unavailable() -> None:
	global _unavailable_warning_emitted
	if _unavailable_warning_emitted:
		return
	_unavailable_warning_emitted = True
	logger.warning(
		'Optional aiosmb-compression package is not installed or usable; '
		'continuing without SMB compression support'
	)


def require_available(algorithm: SMB2CompressionType = None) -> None:
	available = supported_algorithms()
	if algorithm is None and available:
		return
	if algorithm in available:
		return
	if algorithm is None:
		detail = 'at least one unchained SMB compression codec'
	else:
		detail = algorithm.name
	raise SMBCompressionUnavailable(
		'SMB compression requires a usable optional aiosmb-compression '
		'package with %s support' % detail
	)


def _codec_functions(algorithm: SMB2CompressionType):
	for candidate, compressor_name, decompressor_name in _CODECS:
		if candidate == algorithm:
			require_available(algorithm)
			native = _load_native()
			return (
				getattr(native, compressor_name),
				getattr(native, decompressor_name),
			)
	if not isinstance(algorithm, SMB2CompressionType):
		raise TypeError('algorithm must be an SMB2CompressionType value')
	raise ValueError('Unsupported SMB compression algorithm: %s' % algorithm.name)


def compress(algorithm: SMB2CompressionType, data: bytes) -> bytes:
	compressor, _ = _codec_functions(algorithm)
	return compressor(data)


def decompress(
	algorithm: SMB2CompressionType,
	data: bytes,
	expected_size: int,
	max_output_size: int,
) -> bytes:
	_, decompressor = _codec_functions(algorithm)
	return decompressor(data, expected_size, max_output_size)
