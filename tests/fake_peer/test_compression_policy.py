"""SMB 3.1.1 compression policy and partial-transform behavior."""

import asyncio
import zlib
from types import SimpleNamespace

import pytest

from aiosmb.protocol.common import NegotiateDialects
from aiosmb.protocol.compression import backend as compression_backend
from aiosmb.protocol.smb2.command_codes import SMB2Command
from aiosmb.protocol.smb2.commands import ECHO_REQ, WRITE_REQ
from aiosmb.protocol.smb2.commands.read import ReadFlag
from aiosmb.protocol.smb2.commands.negotiate import (
    SMB2CompressionFlags,
    SMB2CompressionType,
)
from aiosmb.protocol.smb2.headers.compression import (
    SMB2Header_COMPRESSION_TRANSFORM,
)
from aiosmb.protocol.smb2.message import SMB2Compression
from aiosmb.wintypes.ntstatus import NTStatus
from tests.support.smb_connection import make_connection, make_request


pytestmark = [pytest.mark.fake_peer, pytest.mark.asyncio]


@pytest.fixture
def compression_connection(monkeypatch: pytest.MonkeyPatch):
    connection = make_connection(dialect=NegotiateDialects.SMB311)
    connection.CompressionIds = [SMB2CompressionType.LZ77]
    connection.CompressionId = SMB2CompressionType.LZ77
    connection.compression_min_size = 1

    monkeypatch.setattr(
        compression_backend,
        "compress",
        lambda algorithm, data: zlib.compress(data),
    )
    monkeypatch.setattr(
        compression_backend,
        "decompress",
        lambda algorithm, data, expected_size, max_output_size: zlib.decompress(
            data
        ),
    )
    return connection


async def test_share_policy_requests_a_compressed_read_response(
    compression_connection,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = compression_connection
    tree_id = 3
    file_id = 5
    captured = {}
    connection.TreeConnectTable_id[tree_id] = SimpleNamespace(compress=True)
    connection.FileHandleTable[file_id] = SimpleNamespace(
        oplock=asyncio.Semaphore(1)
    )

    async def fake_send(message, fh=None, **kwargs):
        captured["message"] = message
        return 11, None

    async def fake_recv(message_id):
        return (
            SimpleNamespace(
                header=SimpleNamespace(Status=NTStatus.SUCCESS),
                command=SimpleNamespace(Buffer=b"data", DataRemaining=0),
            ),
            b"",
            None,
        )

    monkeypatch.setattr(connection, "sendSMB", fake_send)
    monkeypatch.setattr(connection, "recvSMB", fake_recv)

    data, remaining, error = await connection.read(
        tree_id,
        file_id,
        length=4096,
    )

    assert error is None
    assert data == b"data"
    assert remaining == 0
    assert (
        captured["message"].command.Flags
        & ReadFlag.SMB2_READFLAG_REQUEST_COMPRESSED
    )


async def test_per_call_override_can_disable_share_read_compression(
    compression_connection,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = compression_connection
    tree_id = 7
    file_id = 9
    captured = {}
    connection.TreeConnectTable_id[tree_id] = SimpleNamespace(compress=True)
    connection.FileHandleTable[file_id] = SimpleNamespace(
        oplock=asyncio.Semaphore(1)
    )

    async def fake_send(message, fh=None, **kwargs):
        captured["message"] = message
        return 12, None

    async def fake_recv(message_id):
        return (
            SimpleNamespace(
                header=SimpleNamespace(Status=NTStatus.SUCCESS),
                command=SimpleNamespace(Buffer=b"", DataRemaining=0),
            ),
            b"",
            None,
        )

    monkeypatch.setattr(connection, "sendSMB", fake_send)
    monkeypatch.setattr(connection, "recvSMB", fake_recv)

    _, _, error = await connection.read(
        tree_id,
        file_id,
        length=4096,
        compress=False,
    )

    assert error is None
    assert captured["message"].command.Flags == 0


@pytest.mark.parametrize(
    "algorithm",
    [
        SMB2CompressionType.LZ77,
        SMB2CompressionType.LZ77_Huffman,
        SMB2CompressionType.LZ4,
        SMB2CompressionType.LZNT1,
    ],
)
async def test_write_transform_leaves_header_prefix_uncompressed(
    compression_connection,
    algorithm: SMB2CompressionType,
) -> None:
    connection = compression_connection
    connection.CompressionIds = [algorithm]
    connection.CompressionId = algorithm
    command = WRITE_REQ()
    command.Offset = 0
    command.FileId = 0x1234
    command.Data = b"A" * 8192
    message = make_request(
        command,
        command=SMB2Command.WRITE,
        message_id=21,
    )
    plain = message.to_bytes()

    compressed = await connection.compress_message(message)

    assert isinstance(compressed, SMB2Compression)
    assert compressed.header.CompressionAlgorithm is algorithm
    assert compressed.header.Offset == command.DataOffset == 112
    assert compressed.data[: command.DataOffset] == plain[: command.DataOffset]
    assert zlib.decompress(compressed.data[command.DataOffset :]) == command.Data
    assert compressed.header.OriginalCompressedSegmentSize == len(command.Data)


@pytest.mark.parametrize(
    "algorithm",
    [
        SMB2CompressionType.LZ77,
        SMB2CompressionType.LZ77_Huffman,
        SMB2CompressionType.LZ4,
        SMB2CompressionType.LZNT1,
    ],
)
async def test_inbound_transform_dispatches_every_negotiated_algorithm(
    compression_connection,
    algorithm: SMB2CompressionType,
) -> None:
    connection = compression_connection
    connection.CompressionIds = [algorithm]
    plain = make_request(ECHO_REQ(), message_id=31).to_bytes()
    header = SMB2Header_COMPRESSION_TRANSFORM()
    header.OriginalCompressedSegmentSize = len(plain)
    header.CompressionAlgorithm = algorithm
    header.Flags = SMB2CompressionFlags.NONE
    header.Offset = 0

    observed = await connection._decompress_message(
        SMB2Compression(header, zlib.compress(plain))
    )

    assert observed == plain


async def test_inbound_transform_rejects_declared_output_over_connection_limit(
    compression_connection,
) -> None:
    connection = compression_connection
    connection.MaxTransactSize = 16
    connection.MaxReadSize = 16
    connection.MaxWriteSize = 16
    header = SMB2Header_COMPRESSION_TRANSFORM()
    header.OriginalCompressedSegmentSize = connection._compression_output_limit() + 1
    header.CompressionAlgorithm = SMB2CompressionType.LZ77
    header.Flags = SMB2CompressionFlags.NONE
    header.Offset = 0

    with pytest.raises(ValueError, match="connection limit"):
        await connection._decompress_message(SMB2Compression(header, b"encoded"))


async def test_inbound_transform_requires_exact_decoded_size(
    compression_connection,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = compression_connection
    header = SMB2Header_COMPRESSION_TRANSFORM()
    header.OriginalCompressedSegmentSize = 2
    header.CompressionAlgorithm = SMB2CompressionType.LZ77
    header.Flags = SMB2CompressionFlags.NONE
    header.Offset = 0
    monkeypatch.setattr(
        compression_backend,
        "decompress",
        lambda algorithm, data, expected_size, max_output_size: b"x",
    )

    with pytest.raises(ValueError, match="output length"):
        await connection._decompress_message(SMB2Compression(header, b"encoded"))


async def test_inbound_transform_requires_an_smb2_inner_message(
    compression_connection,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = compression_connection
    header = SMB2Header_COMPRESSION_TRANSFORM()
    header.OriginalCompressedSegmentSize = 4
    header.CompressionAlgorithm = SMB2CompressionType.LZ77
    header.Flags = SMB2CompressionFlags.NONE
    header.Offset = 0
    monkeypatch.setattr(
        compression_backend,
        "decompress",
        lambda algorithm, data, expected_size, max_output_size: b"\xffSMB",
    )

    with pytest.raises(ValueError, match="not an SMB2"):
        await connection._decompress_message(SMB2Compression(header, b"encoded"))
