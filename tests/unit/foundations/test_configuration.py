"""Offline tests for connection configuration contracts."""

import importlib

import pytest

from aiosmb.commons.connection.target import SMBConnectionDialect, SMBTarget
from aiosmb.protocol.common import NegotiateDialects


pytestmark = pytest.mark.unit


@pytest.mark.xfail(
    strict=True,
    reason="KF-0100: connection parameter configuration imports a missing module",
)
def test_connection_parameter_configuration_is_importable() -> None:
    module = importlib.import_module("aiosmb.commons.connection.params")

    assert callable(module.SMBConnectionParams.extend_parser)
    assert callable(module.SMBConnectionParams.parse_args)


@pytest.mark.parametrize(
    "fragment,expected_size",
    [
        (None, 1024 * 1024),
        (1, 5000 * 1024),
        (2, 500 * 1024),
        (3, 10 * 1024),
        (4, 7 * 1024),
        (5, 5 * 1024),
    ],
)
def test_fragment_profiles_configure_all_io_limits(
    fragment: int, expected_size: int
) -> None:
    target = SMBTarget(ip="192.0.2.10", fragment=fragment)

    assert (
        target.MaxTransactSize,
        target.MaxReadSize,
        target.MaxWriteSize,
    ) == (expected_size, expected_size, expected_size)


@pytest.mark.parametrize(
    "dialect,expected",
    [
        (
            SMBConnectionDialect.SMB2,
            {NegotiateDialects.SMB202, NegotiateDialects.SMB210},
        ),
        (
            SMBConnectionDialect.SMB3,
            {
                NegotiateDialects.SMB300,
                NegotiateDialects.SMB302,
                NegotiateDialects.SMB311,
            },
        ),
        (
            SMBConnectionDialect.SMB311,
            {NegotiateDialects.SMB311, NegotiateDialects.WILDCARD},
        ),
    ],
)
def test_dialect_profiles_offer_only_the_configured_family(
    dialect: SMBConnectionDialect, expected: set
) -> None:
    target = SMBTarget(ip="192.0.2.10")

    target.update_dialect(dialect)

    assert set(target.preferred_dialects) == expected
    assert set(target.preferred_dialects.values()) == {1}


def test_dialect_configuration_rejects_non_enum_values() -> None:
    target = SMBTarget(ip="192.0.2.10")

    with pytest.raises(Exception, match="dialect must be"):
        target.update_dialect("SMB3")
