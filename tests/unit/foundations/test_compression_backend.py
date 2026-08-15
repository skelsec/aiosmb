"""Optional native SMB compression backend contracts."""

from types import SimpleNamespace

import pytest

from aiosmb.connection import SMBConnection
from aiosmb.commons.connection.target import SMBTarget
from aiosmb.protocol.common import NegotiateDialects
from aiosmb.protocol.compression import backend
from aiosmb.protocol.compression import lznt1 as python_lznt1
from aiosmb.protocol.smb2.commands.negotiate import SMB2CompressionType


pytestmark = pytest.mark.unit


def test_default_backend_reports_no_algorithms_when_native_module_is_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(backend, "_native", None)

    assert backend.is_available() is False
    assert backend.supported_algorithms() == ()
    with pytest.raises(backend.SMBCompressionUnavailable):
        backend.require_available()


def test_default_connection_warns_once_when_optional_native_module_is_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(backend, "_native", backend._NATIVE_UNSET)
    monkeypatch.setattr(backend, "_unavailable_warning_emitted", False)
    imports = []
    warnings = []

    def missing_import(name):
        imports.append(name)
        raise ImportError(name)

    monkeypatch.setattr(backend.importlib, "import_module", missing_import)
    monkeypatch.setattr(backend.logger, "warning", warnings.append)

    connections = []
    for _ in range(2):
        target = SMBTarget(ip="127.0.0.1")
        target.preferred_dialects = [NegotiateDialects.SMB311]
        connections.append(
            SMBConnection(None, target, preserve_gssapi=False)
        )

    assert imports == ["aiosmb_compression"]
    assert len(warnings) == 1
    assert all(connection.CompressionIds is None for connection in connections)


def test_native_backend_dispatches_all_available_codecs_with_bounded_decode_arguments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = []
    native = SimpleNamespace()
    names = (
        (SMB2CompressionType.LZ77, "lz77"),
        (SMB2CompressionType.LZ77_Huffman, "lz77_huffman"),
        (SMB2CompressionType.LZ4, "lz4"),
        (SMB2CompressionType.LZNT1, "lznt1"),
    )
    for algorithm, name in names:
        setattr(
            native,
            "compress_" + name,
            lambda data, current=algorithm: current.name.encode() + b":" + data,
        )
        setattr(
            native,
            "decompress_" + name,
            lambda data, expected, maximum, current=algorithm: calls.append(
                (current, data, expected, maximum)
            )
            or b"decoded",
        )
    monkeypatch.setattr(backend, "_native", native)

    assert backend.supported_algorithms() == tuple(item[0] for item in names)
    for algorithm, _ in names:
        assert backend.compress(algorithm, b"input") == (
            algorithm.name.encode() + b":input"
        )
        assert backend.decompress(algorithm, b"wire", 7, 1024) == b"decoded"
    assert calls == [
        (algorithm, b"wire", 7, 1024)
        for algorithm, _ in names
    ]


def test_partial_native_backend_reports_only_complete_codec_pairs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        backend,
        "_native",
        SimpleNamespace(
            compress_lz77=lambda data: data,
            decompress_lz77=lambda data, expected, maximum: data,
            compress_lz4=lambda data: data,
        ),
    )

    assert backend.supported_algorithms() == (SMB2CompressionType.LZ77,)
    with pytest.raises(backend.SMBCompressionUnavailable, match="LZ4"):
        backend.compress(SMB2CompressionType.LZ4, b"input")


def test_explicit_connection_compression_degrades_when_native_extra_is_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(backend, "_native", None)
    monkeypatch.setattr(backend, "_unavailable_warning_emitted", False)
    warnings = []
    monkeypatch.setattr(backend.logger, "warning", warnings.append)
    target = SMBTarget(ip="127.0.0.1", compression=True)
    target.preferred_dialects = [NegotiateDialects.SMB311]

    connection = SMBConnection(None, target, preserve_gssapi=False)

    assert connection.CompressionIds is None
    assert connection.CompressAllRequests is True
    assert len(warnings) == 1


def test_algorithm_preference_degrades_when_native_extra_is_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(backend, "_native", None)
    monkeypatch.setattr(backend, "_unavailable_warning_emitted", False)
    warnings = []
    monkeypatch.setattr(backend.logger, "warning", warnings.append)
    target = SMBTarget(
        ip="127.0.0.1",
        compression_algorithms=(SMB2CompressionType.LZ4,),
    )
    target.preferred_dialects = [NegotiateDialects.SMB311]

    connection = SMBConnection(None, target, preserve_gssapi=False)

    assert connection.CompressionIds is None
    assert connection.CompressAllRequests is False
    assert len(warnings) == 1


def test_connection_advertises_all_native_codecs_in_preference_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        backend, "supported_algorithms", lambda: (
            SMB2CompressionType.LZ77,
            SMB2CompressionType.LZ77_Huffman,
            SMB2CompressionType.LZ4,
            SMB2CompressionType.LZNT1,
        )
    )
    monkeypatch.setattr(backend, "require_available", lambda algorithm=None: None)
    target = SMBTarget(ip="127.0.0.1")
    target.preferred_dialects = [NegotiateDialects.SMB311]

    connection = SMBConnection(None, target, preserve_gssapi=False)

    assert connection.CompressionIds == [
        SMB2CompressionType.LZ77,
        SMB2CompressionType.LZ77_Huffman,
        SMB2CompressionType.LZ4,
        SMB2CompressionType.LZNT1,
    ]
    assert connection.CompressAllRequests is False
    assert connection.SupportsChainedCompression is False


def test_compress_all_policy_remains_explicit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        backend,
        "supported_algorithms",
        lambda: (SMB2CompressionType.LZ77,),
    )
    target = SMBTarget(ip="127.0.0.1", compression=True)
    target.preferred_dialects = [NegotiateDialects.SMB311]

    connection = SMBConnection(None, target, preserve_gssapi=False)

    assert connection.CompressionIds == [SMB2CompressionType.LZ77]
    assert connection.CompressAllRequests is True


def test_connection_preserves_requested_available_algorithm_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        backend,
        "supported_algorithms",
        lambda: (SMB2CompressionType.LZ77, SMB2CompressionType.LZ4),
    )
    monkeypatch.setattr(backend, "require_available", lambda algorithm=None: None)
    target = SMBTarget(
        ip="127.0.0.1",
        compression_algorithms=(
            SMB2CompressionType.LZ4,
            SMB2CompressionType.LZNT1,
            SMB2CompressionType.LZ77,
        ),
    )
    target.preferred_dialects = [NegotiateDialects.SMB311]

    connection = SMBConnection(None, target, preserve_gssapi=False)

    assert connection.CompressionIds == [
        SMB2CompressionType.LZ4,
        SMB2CompressionType.LZ77,
    ]
    assert connection.CompressAllRequests is False


def test_connection_rejects_compression_without_smb311(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(backend, "_native", SimpleNamespace())
    target = SMBTarget(ip="127.0.0.1", compression=True)

    with pytest.raises(ValueError, match="SMB 3.1.1"):
        SMBConnection(None, target, preserve_gssapi=False)


@pytest.mark.parametrize(
    "algorithm",
    [
        SMB2CompressionType.LZ77,
        SMB2CompressionType.LZ77_Huffman,
        SMB2CompressionType.LZ4,
        SMB2CompressionType.LZNT1,
    ],
)
def test_installed_native_backend_round_trip(algorithm: SMB2CompressionType) -> None:
    if algorithm not in backend.supported_algorithms():
        pytest.skip("codec is not available from the installed native package")
    plain = (bytes(range(256)) * 8) + (b"aiosmb-xpress" * 1024)

    compressed = backend.compress(algorithm, plain)
    decoded = backend.decompress(
        algorithm,
        compressed,
        len(plain),
        len(plain),
    )

    assert decoded == plain


def test_native_lznt1_interoperates_with_retained_python_reference() -> None:
    if SMB2CompressionType.LZNT1 not in backend.supported_algorithms():
        pytest.skip("native LZNT1 is not available")
    plain = (b"native-python-lznt1-parity-" * 256) + bytes(range(256))

    native_encoded = backend.compress(SMB2CompressionType.LZNT1, plain)
    assert python_lznt1.decompress(native_encoded) == plain

    python_encoded = python_lznt1.compress(plain)
    assert backend.decompress(
        SMB2CompressionType.LZNT1,
        python_encoded,
        len(plain),
        len(plain),
    ) == plain
