"""Separately gated privileged, read-only Windows paths."""

import sys

import pytest

if sys.version_info < (3, 9):
    pytest.skip("blocked by KF-0107", allow_module_level=True)

from aiosmb.commons.interfaces.machine import SMBMachine

from ._lab import (
    capability_error,
    logged_in,
    require_runtime_capability,
)


pytestmark = [
    pytest.mark.windows,
    pytest.mark.asyncio,
    pytest.mark.privileged,
]


async def test_admin_enumerates_services_read_only(
    windows_privileged_target,
) -> None:
    windows_privileged_target.require_declared_capability("service_read")

    async with logged_in(windows_privileged_target, "admin") as connection:
        count = 0
        async for service, error in SMBMachine(connection).list_services():
            capability_error(error, "service_read")
            assert service is not None
            count += 1

    assert count > 0


async def test_admin_reads_windows_directory_from_registry(
    windows_privileged_target,
) -> None:
    windows_privileged_target.require_declared_capability("registry_read")

    async with logged_in(windows_privileged_target, "admin") as connection:
        path, error = await SMBMachine(
            connection
        ).reg_get_windows_directory_path()
        capability_error(error, "registry_read")

    assert path
    assert ":\\" in path


async def test_domain_admin_reads_dc_ntds_path(
    windows_privileged_target, windows_metadata
) -> None:
    windows_privileged_target.require_declared_capability("dc_registry_read")
    require_runtime_capability(windows_metadata, "directory_service")

    async with logged_in(
        windows_privileged_target, "domain_admin"
    ) as connection:
        path, error = await SMBMachine(connection).reg_get_ntds_file_path()
        capability_error(error, "dc_registry_read")

    assert path
    assert path.lower().endswith("ntds.dit")


@pytest.mark.parametrize(
    "tier,capability",
    [
        pytest.param("machine", "machine_auth", id="machine"),
        pytest.param("certificate", "certificate_auth", id="certificate"),
    ],
)
async def test_explicit_identity_tier_authenticates_without_mutation(
    windows_privileged_target, tier, capability, record_property
) -> None:
    windows_privileged_target.require_declared_capability(capability)

    async with logged_in(windows_privileged_target, tier) as connection:
        record_property("windows_target", windows_privileged_target.id)
        record_property("credential_tier", tier)
        assert connection.login_ok is True
        assert connection.SessionId != 0
