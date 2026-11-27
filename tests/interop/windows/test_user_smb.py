"""Normal-user, non-destructive SMB interoperability coverage."""

import hashlib
import sys

import pytest

if sys.version_info < (3, 9):
    pytest.skip("blocked by KF-0107", allow_module_level=True)

from aiosmb.commons.interfaces.file import SMBFile
from aiosmb.commons.interfaces.machine import SMBMachine

from ._lab import capability_error, logged_in


pytestmark = [pytest.mark.windows, pytest.mark.asyncio]


async def test_normal_user_can_authenticate(
    windows_user_target, record_property
) -> None:
    async with logged_in(windows_user_target, "user") as connection:
        record_property("windows_target", windows_user_target.id)
        record_property("credential_tier", "user")
        record_property(
            "negotiated_dialect", connection.selected_dialect.name
        )
        assert connection.login_ok is True
        assert connection.SessionId != 0
        assert connection.selected_dialect.name != "WILDCARD"


async def test_normal_user_can_enumerate_shares(
    windows_user_target,
) -> None:
    windows_user_target.require_declared_capability("share_enumeration")

    async with logged_in(windows_user_target, "user") as connection:
        machine = SMBMachine(connection)
        shares = []
        async for share, error in machine.list_shares():
            capability_error(error, "share_enumeration")
            assert share is not None
            shares.append(share.name.upper())

    assert shares
    assert "IPC$" in shares


async def test_normal_user_reads_only_explicitly_safe_files(
    windows_user_target,
) -> None:
    if not windows_user_target.safe_reads:
        pytest.skip("profile declares no safe read-only files")

    async with logged_in(windows_user_target, "user") as connection:
        for item in windows_user_target.safe_reads:
            share = item.get("share")
            path = item.get("path")
            if not share or not path:
                pytest.fail(
                    "safe_reads entries require share and path", pytrace=False
                )
            maximum = int(item.get("max_bytes", 1024 * 1024))
            remote_file = SMBFile.from_uncpath(
                windows_user_target.unc_path(str(share), str(path))
            )
            opened, error = await remote_file.open(connection, mode="r")
            capability_error(error, "safe_file_read")
            assert opened is not False
            try:
                assert remote_file.size <= maximum, (
                    "safe file exceeds configured max_bytes"
                )
                data, error = await remote_file.read(maximum)
                capability_error(error, "safe_file_read")
                assert data is not None
                expected_digest = item.get("sha256")
                if expected_digest:
                    assert hashlib.sha256(data).hexdigest() == expected_digest
            finally:
                await remote_file.close()
