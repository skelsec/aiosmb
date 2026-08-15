"""Deterministic signing, integrity, compression, and encryption checks."""

import asyncio
import hashlib
import hmac
import threading
import zlib

import pytest

from aiosmb.protocol.common import NegotiateDialects
from aiosmb.protocol.compression import backend as compression_backend
from aiosmb.protocol.smb2.commands import ECHO_REQ
from aiosmb.protocol.smb2.commands.negotiate import (
    SMB2Cipher,
    SMB2CompressionFlags,
    SMB2CompressionType,
)
from aiosmb.protocol.smb2.headers import SMB2HeaderFlag
from aiosmb.protocol.smb2.message import (
    SMB2Compression,
    SMB2Message,
    SMB2Transform,
)
from tests.support.scripted_smb import ScriptedSMBTransport
from tests.support.smb_connection import make_connection, make_request


pytestmark = [pytest.mark.fake_peer, pytest.mark.asyncio]
TIMEOUT = 0.5


@pytest.fixture
def fake_compression_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    def compress(algorithm, data):
        assert algorithm in (
            SMB2CompressionType.LZ77,
            SMB2CompressionType.LZ77_Huffman,
            SMB2CompressionType.LZ4,
            SMB2CompressionType.LZNT1,
        )
        return zlib.compress(data)

    def decompress(algorithm, data, expected_size, max_output_size):
        assert algorithm in (
            SMB2CompressionType.LZ77,
            SMB2CompressionType.LZ77_Huffman,
            SMB2CompressionType.LZ4,
            SMB2CompressionType.LZNT1,
        )
        decoded = zlib.decompress(data)
        if len(decoded) != expected_size or len(decoded) > max_output_size:
            raise ValueError("invalid decoded size")
        return decoded

    monkeypatch.setattr(compression_backend, "compress", compress)
    monkeypatch.setattr(compression_backend, "decompress", decompress)


async def test_preauth_integrity_chains_each_wire_message() -> None:
    connection = make_connection(dialect=NegotiateDialects.SMB311)
    initial = b"\x11" * 64
    first = b"first negotiate frame"
    second = b"second negotiate frame"
    connection.PreauthIntegrityHashValue = initial

    connection.update_integrity(first)
    expected_first = hashlib.sha512(initial + first).digest()
    assert connection.PreauthIntegrityHashValue == expected_first

    connection.update_integrity(second)
    assert connection.PreauthIntegrityHashValue == hashlib.sha512(
        expected_first + second
    ).digest()


async def test_smb210_signing_matches_hmac_sha256_wire_contract() -> None:
    key = bytes(range(16))
    connection = make_connection(dialect=NegotiateDialects.SMB210)
    connection.SessionKey = key
    message = make_request(ECHO_REQ(), message_id=9)
    expected_message = make_request(ECHO_REQ(), message_id=9)
    expected_message.header.Flags = SMB2HeaderFlag.SMB2_FLAGS_SIGNED
    expected = hmac.new(
        key, expected_message.to_bytes(), hashlib.sha256
    ).digest()[:16]

    connection.sign_message(message)

    assert message.header.Flags & SMB2HeaderFlag.SMB2_FLAGS_SIGNED
    assert message.header.Signature == expected


async def test_send_path_emits_signed_smb210_request() -> None:
    connection = make_connection(dialect=NegotiateDialects.SMB210)
    connection.SessionKey = b"\x5a" * 16
    connection.signing_required = True
    transport = ScriptedSMBTransport()
    connection.network_connection = transport

    message_id, error = await connection.sendSMB(make_request(ECHO_REQ()))

    assert error is None
    assert message_id == 0
    wire = transport.writes[0]
    flags = int.from_bytes(wire[16:20], "little")
    assert flags & SMB2HeaderFlag.SMB2_FLAGS_SIGNED.value
    assert wire[48:64] != b"\x00" * 16
    await transport.close()


async def test_smb311_signing_marks_packet_as_signed() -> None:
    connection = make_connection(dialect=NegotiateDialects.SMB311)
    connection.SigningKey = b"\xa5" * 16
    message = make_request(ECHO_REQ(), message_id=12)

    connection.sign_message(message)

    assert message.header.Flags & SMB2HeaderFlag.SMB2_FLAGS_SIGNED
    assert message.header.Signature != b"\x00" * 16


async def test_smb311_signature_verification_rejects_tampering() -> None:
    connection = make_connection(dialect=NegotiateDialects.SMB311)
    connection.SigningKey = b"\xa5" * 16
    message = make_request(ECHO_REQ(), message_id=13)
    connection.sign_message(message)
    wire = message.to_bytes()

    assert connection.verify_message(message, wire) is True

    tampered = wire[:-1] + bytes([wire[-1] ^ 1])
    with pytest.raises(ValueError, match="verification failed"):
        connection.verify_message(message, tampered)


@pytest.mark.parametrize(
    "algorithm",
    [
        SMB2CompressionType.LZ77,
        SMB2CompressionType.LZ77_Huffman,
        SMB2CompressionType.LZ4,
        SMB2CompressionType.LZNT1,
    ],
)
async def test_compression_is_deterministic_and_reversible_for_every_codec(
    fake_compression_backend,
    algorithm: SMB2CompressionType,
) -> None:
    connection = make_connection(dialect=NegotiateDialects.SMB311)
    connection.CompressionIds = [algorithm]
    connection.CompressionId = algorithm
    connection.compression_min_size = 1
    message = make_request(ECHO_REQ(), message_id=15)
    plain = message.to_bytes()

    first = (await connection.compress_message(message)).to_bytes()
    second = (await connection.compress_message(message)).to_bytes()
    parsed = SMB2Compression.from_bytes(first)

    assert first == second
    assert parsed.header.CompressionAlgorithm == algorithm
    assert parsed.header.Flags == SMB2CompressionFlags.NONE
    assert parsed.header.Offset == 0
    assert parsed.header.OriginalCompressedSegmentSize == len(plain)
    assert zlib.decompress(parsed.data) == plain


async def test_incompressible_message_is_sent_without_transform(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = make_connection(dialect=NegotiateDialects.SMB311)
    connection.CompressionIds = [SMB2CompressionType.LZ77]
    connection.CompressionId = SMB2CompressionType.LZ77
    connection.compression_min_size = 1
    monkeypatch.setattr(
        compression_backend,
        "compress",
        lambda algorithm, data: data + b"larger",
    )

    assert (
        await connection.compress_message(make_request(ECHO_REQ(), message_id=16))
        is None
    )


async def test_compression_offload_keeps_event_loop_responsive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    started = threading.Event()
    release = threading.Event()
    loop_progressed = False
    connection = make_connection(dialect=NegotiateDialects.SMB311)
    connection.CompressionIds = [SMB2CompressionType.LZ77]
    connection.CompressionId = SMB2CompressionType.LZ77
    connection.compression_min_size = 1

    def blocking_compress(algorithm, data):
        started.set()
        release.wait(timeout=1)
        return b"x"

    monkeypatch.setattr(compression_backend, "compress", blocking_compress)
    task = asyncio.create_task(
        connection.compress_message(make_request(ECHO_REQ(), message_id=17))
    )
    while not started.is_set():
        await asyncio.sleep(0)
    await asyncio.sleep(0)
    loop_progressed = True
    release.set()

    assert await task is not None
    assert loop_progressed is True


async def test_cancelled_compression_keeps_worker_slot_until_codec_finishes() -> None:
    started = threading.Event()
    release = threading.Event()
    calls = []
    connection = make_connection(dialect=NegotiateDialects.SMB311)

    def codec(value):
        calls.append(value)
        if value == b"first":
            started.set()
            release.wait(timeout=1)
        return value

    first = asyncio.create_task(
        connection._run_compression_codec(codec, b"first")
    )
    while not started.is_set():
        await asyncio.sleep(0)
    first.cancel()
    second = asyncio.create_task(
        connection._run_compression_codec(codec, b"second")
    )
    for _ in range(5):
        await asyncio.sleep(0)

    assert calls == [b"first"]
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await first
    assert await second == b"second"
    assert calls == [b"first", b"second"]


@pytest.mark.parametrize(
    "cipher,nonce",
    [
        (SMB2Cipher.AES_128_CCM, b"\x21" * 11),
        pytest.param(
            SMB2Cipher.AES_128_GCM,
            b"\x32" * 12,
            marks=pytest.mark.xfail(
                strict=True,
                reason="KF-0506: AES-GCM helper passes an invalid MAC length",
            ),
        ),
    ],
)
async def test_encryption_is_deterministic_with_fixed_key_and_nonce(
    monkeypatch: pytest.MonkeyPatch,
    cipher: SMB2Cipher,
    nonce: bytes,
) -> None:
    connection = make_connection(dialect=NegotiateDialects.SMB311)
    connection.CipherId = cipher
    connection.EncryptionKey = bytes(range(16))
    connection.SessionId = 0x1020304050607080
    monkeypatch.setattr("aiosmb.connection.os.urandom", lambda size: nonce)
    plain = make_request(ECHO_REQ(), message_id=18).to_bytes()

    first = connection.encrypt_message(plain).to_bytes()
    second = connection.encrypt_message(plain).to_bytes()
    parsed = SMB2Transform.from_bytes(first)

    assert first == second
    assert parsed.header.EncryptionAlgorithm == cipher
    assert parsed.header.OriginalMessageSize == len(plain)
    assert parsed.header.SessionId == connection.SessionId
    assert parsed.header.Nonce.startswith(nonce)
    assert parsed.header.Signature != b"\x00" * 16
    assert parsed.data != plain


async def test_send_path_compresses_then_encrypts_without_redundant_signing(
    monkeypatch: pytest.MonkeyPatch,
    fake_compression_backend,
) -> None:
    connection = make_connection(dialect=NegotiateDialects.SMB311)
    connection.CompressionIds = [SMB2CompressionType.LZ77]
    connection.CompressionId = SMB2CompressionType.LZ77
    connection.compression_min_size = 1
    connection.CipherId = SMB2Cipher.AES_128_CCM
    connection.EncryptionKey = b"\x44" * 16
    connection.encryption_required = True
    connection.SigningKey = b"\x66" * 16
    connection.signing_required = True
    monkeypatch.setattr(
        "aiosmb.connection.os.urandom", lambda size: b"\x55" * size
    )
    transport = ScriptedSMBTransport()
    connection.network_connection = transport

    message_id, error = await connection.sendSMB(
        make_request(ECHO_REQ()),
        compress=True,
    )

    assert error is None
    assert message_id == 0
    wire = transport.writes[0]
    transform = SMB2Transform.from_bytes(wire)
    assert transform.header.EncryptionAlgorithm == SMB2Cipher.AES_128_CCM
    from unicrypto.symmetric import AES, MODE_CCM

    decryptor = AES(
        connection.EncryptionKey,
        MODE_CCM,
        transform.header.Nonce[:11],
        segment_size=16,
    )
    nested = decryptor.decrypt(
        transform.data,
        wire[20:52],
        transform.header.Signature,
    )
    compressed = SMB2Compression.from_bytes(nested)
    assert compressed.header.CompressionAlgorithm is SMB2CompressionType.LZ77
    inner_wire = (
        compressed.data[: compressed.header.Offset]
        + zlib.decompress(compressed.data[compressed.header.Offset :])
    )
    inner = SMB2Message.from_bytes(inner_wire)
    assert not inner.header.Flags & SMB2HeaderFlag.SMB2_FLAGS_SIGNED
    assert inner.header.Signature == b"\x00" * 16
    await transport.close()
