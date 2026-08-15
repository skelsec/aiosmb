"""Read-only SRVSVC, SAMR, LSA, and directory-service paths."""

import sys

import pytest

if sys.version_info < (3, 9):
    pytest.skip("blocked by KF-0107", allow_module_level=True)

from aiosmb.commons.interfaces.machine import SMBMachine
from aiosmb.dcerpc.v5 import lsat
from aiosmb.dcerpc.v5.interfaces.lsatmgr import lsadrpc_from_smb

from ._lab import (
    capability_error,
    logged_in,
    require_runtime_capability,
)


pytestmark = [pytest.mark.windows, pytest.mark.asyncio]


async def test_srvsvc_read_path(windows_user_target) -> None:
    windows_user_target.require_declared_capability("srvsvc_read")

    async with logged_in(windows_user_target, "user") as connection:
        names = []
        async for share, error in SMBMachine(connection).list_shares():
            capability_error(error, "srvsvc_read")
            assert share is not None
            names.append(share.name)

    assert names


async def test_samr_lists_account_domains(windows_user_target) -> None:
    windows_user_target.require_declared_capability("samr_read")

    async with logged_in(windows_user_target, "user") as connection:
        domains = []
        async for domain, error in SMBMachine(connection).list_domains():
            capability_error(error, "samr_read")
            assert domain is not None
            domains.append(domain.upper())

    assert "BUILTIN" in domains
    assert str(
        windows_user_target.expected["netbios_domain"]
    ).upper() in domains


async def test_lsa_reads_primary_domain_sid(windows_user_target) -> None:
    windows_user_target.require_declared_capability("lsa_read")

    async with logged_in(windows_user_target, "user") as connection:
        try:
            async with lsadrpc_from_smb(connection) as rpc:
                permissions = (
                    lsat.POLICY_VIEW_LOCAL_INFORMATION
                    | lsat.POLICY_LOOKUP_NAMES
                )
                policy, error = await rpc.open_policy2(
                    permissions=permissions
                )
                capability_error(error, "lsa_read")
                sid, error = await rpc.get_domain_sid(policy)
                capability_error(error, "lsa_read")
        except Exception as error:
            capability_error(error, "lsa_read")

    assert sid.startswith("S-1-")


async def test_dc_samr_lists_domain_users_as_read_only_metadata(
    windows_user_target, windows_metadata
) -> None:
    windows_user_target.require_declared_capability("dc_samr_read")
    require_runtime_capability(windows_metadata, "directory_service")

    async with logged_in(windows_user_target, "user") as connection:
        count = 0
        async for username, sid, error in SMBMachine(
            connection
        ).list_domain_users(
            str(windows_user_target.expected["netbios_domain"])
        ):
            capability_error(error, "dc_samr_read")
            assert username is not None
            assert sid is not None
            count += 1

    assert count > 0
