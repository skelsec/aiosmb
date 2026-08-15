"""Opt-in destructive SMB 3.1.1 compression interoperability."""

import sys
import uuid

import pytest

if sys.version_info < (3, 9):
    pytest.skip("native compression requires Python 3.9+", allow_module_level=True)

from aiosmb.commons.interfaces.file import SMBFile
from aiosmb.protocol.smb2.commands.negotiate import SMB2CompressionType

from ._lab import (
    CREDENTIAL_TIERS,
    capability_error,
    logged_in,
    require_destructive_safety,
)


pytestmark = [
    pytest.mark.windows,
    pytest.mark.asyncio,
    pytest.mark.destructive,
    pytest.mark.capability("compression"),
]


@pytest.mark.parametrize(
    "algorithm",
    [
        SMB2CompressionType.LZ77,
        SMB2CompressionType.LZ77_Huffman,
        SMB2CompressionType.LZNT1,
        SMB2CompressionType.LZ4,
    ],
    ids=lambda algorithm: algorithm.name,
)
async def test_compressed_write_and_requested_read_round_trip(
    windows_destructive_target,
    algorithm: SMB2CompressionType,
) -> None:
    windows_destructive_target.require_declared_capability("smb_compression")
    if (
        algorithm is SMB2CompressionType.LZ4
        and int(windows_destructive_target.expected["build"]) < 26100
    ):
        pytest.skip("SMB LZ4 requires Windows 11 or Windows Server 2025")
    settings = require_destructive_safety(
        windows_destructive_target,
        "compression_roundtrip",
    )
    share = settings.get("share")
    directory = str(settings.get("directory", "")).strip("\\/")
    tier = str(settings.get("credential_tier", "user"))
    if not share:
        pytest.fail(
            "compression_roundtrip requires an allow-listed share",
            pytrace=False,
        )
    if tier not in CREDENTIAL_TIERS:
        pytest.fail("compression_roundtrip credential tier is invalid")

    prefix = str(settings.get("prefix", "aiosmb-compression-"))
    filename = "{}{}.bin".format(prefix, uuid.uuid4().hex)
    remote_path = "\\".join(item for item in (directory, filename) if item)
    unc_path = windows_destructive_target.unc_path(str(share), remote_path)
    payload = (b"aiosmb-compression-vector-" * 4096)[: 64 * 1024]

    async with logged_in(
        windows_destructive_target,
        tier,
        compression=True,
        compression_algorithm=algorithm,
    ) as connection:
        assert connection.selected_dialect.name == "SMB311"
        assert connection.CompressionId is algorithm
        outbound_transforms = 0
        inbound_transforms = 0
        original_compress = connection.compress_message
        original_decompress = connection._decompress_message

        async def count_compress(*args, **kwargs):
            nonlocal outbound_transforms
            result = await original_compress(*args, **kwargs)
            if result is not None:
                outbound_transforms += 1
            return result

        async def count_decompress(*args, **kwargs):
            nonlocal inbound_transforms
            inbound_transforms += 1
            return await original_decompress(*args, **kwargs)

        connection.compress_message = count_compress
        connection._decompress_message = count_decompress
        created = False
        writer_closed = False
        writer = SMBFile.from_uncpath(unc_path)
        try:
            opened, error = await writer.open(connection, mode="w")
            capability_error(error, "smb_compression")
            assert opened is not False
            created = True
            written, error = await writer.write(payload)
            capability_error(error, "smb_compression")
            assert written == len(payload)
            await writer.close()
            writer_closed = True

            reader = SMBFile.from_uncpath(unc_path)
            opened, error = await reader.open(connection, mode="r")
            capability_error(error, "smb_compression")
            assert opened is not False
            try:
                observed, error = await reader.read(len(payload))
                capability_error(error, "smb_compression")
                assert observed == payload
            finally:
                await reader.close()

            assert outbound_transforms > 0
            assert inbound_transforms > 0
        finally:
            if not writer_closed:
                await writer.close()
            if created:
                deleted, cleanup_error = await SMBFile.delete_unc(
                    connection,
                    unc_path,
                )
                if cleanup_error is not None or deleted is not True:
                    pytest.fail(
                        "compression test cleanup failed with {}".format(
                            type(cleanup_error).__name__
                            if cleanup_error is not None
                            else "UnknownCleanupFailure"
                        ),
                        pytrace=False,
                    )
