"""Destructive skeletons with explicit disposable and cleanup contracts."""

import sys
import uuid

import pytest

if sys.version_info < (3, 9):
    pytest.skip("blocked by KF-0107", allow_module_level=True)

from aiosmb.commons.interfaces.file import SMBFile

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
]


async def test_disposable_share_file_round_trip_has_deterministic_cleanup(
    windows_destructive_target,
) -> None:
    settings = require_destructive_safety(
        windows_destructive_target, "file_roundtrip"
    )
    share = settings.get("share")
    directory = str(settings.get("directory", "")).strip("\\/")
    tier = str(settings.get("credential_tier", "user"))
    if not share:
        pytest.fail(
            "file_roundtrip requires an allow-listed share", pytrace=False
        )
    if tier not in CREDENTIAL_TIERS:
        pytest.fail("file_roundtrip credential tier is invalid", pytrace=False)

    prefix = str(settings.get("prefix", "aiosmb-interop-"))
    filename = "{}{}.bin".format(prefix, uuid.uuid4().hex)
    remote_path = "\\".join(item for item in (directory, filename) if item)
    unc_path = windows_destructive_target.unc_path(str(share), remote_path)
    payload = b"aiosmb-windows-disposable-round-trip"

    async with logged_in(windows_destructive_target, tier) as connection:
        created = False
        writer_closed = False
        writer = SMBFile.from_uncpath(unc_path)
        try:
            opened, error = await writer.open(connection, mode="w")
            capability_error(error, "destructive_file_roundtrip")
            assert opened is not False
            created = True
            written, error = await writer.write(payload)
            capability_error(error, "destructive_file_roundtrip")
            assert written == len(payload)
            await writer.close()
            writer_closed = True

            reader = SMBFile.from_uncpath(unc_path)
            opened, error = await reader.open(connection, mode="r")
            capability_error(error, "destructive_file_roundtrip")
            assert opened is not False
            try:
                observed, error = await reader.read(len(payload))
                capability_error(error, "destructive_file_roundtrip")
                assert observed == payload
            finally:
                await reader.close()
        finally:
            if not writer_closed:
                await writer.close()
            if created:
                deleted, cleanup_error = await SMBFile.delete_unc(
                    connection, unc_path
                )
                if cleanup_error is not None or deleted is not True:
                    pytest.fail(
                        "deterministic file cleanup failed with {}".format(
                            type(cleanup_error).__name__
                            if cleanup_error is not None
                            else "UnknownCleanupFailure"
                        ),
                        pytrace=False,
                    )
