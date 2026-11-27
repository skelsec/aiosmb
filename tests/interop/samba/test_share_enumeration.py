"""Selected stable SRVSVC interoperability coverage."""

import sys

import pytest

if sys.version_info < (3, 9):
    pytest.skip("blocked by KF-0107", allow_module_level=True)

from aiosmb.commons.interfaces.machine import SMBMachine

from ._lab import logged_in


pytestmark = [
    pytest.mark.samba,
    pytest.mark.asyncio,
    pytest.mark.capability("srvsvc"),
]


async def test_srvsvc_enumerates_configured_and_ipc_shares(samba_profile):
    samba_profile.require_capability("srvsvc")

    async with logged_in(samba_profile) as connection:
        machine = SMBMachine(connection)
        shares = []
        async for share, error in machine.list_shares():
            assert error is None, "SRVSVC enumeration failed with {}".format(
                type(error).__name__
            )
            shares.append(share.name)

    normalized = {name.upper() for name in shares}
    assert samba_profile.share.upper() in normalized
    assert "IPC$" in normalized
