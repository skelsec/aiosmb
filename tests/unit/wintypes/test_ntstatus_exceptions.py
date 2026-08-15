"""NTSTATUS identity and SMB exception behavior tests."""

import pytest

from aiosmb.commons.exceptions import (
    SMBConnectionNetworkTerminated,
    SMBConnectionRefusedException,
    SMBConnectionTerminated,
    SMBConnectionTimeoutException,
    SMBCreateAccessDenied,
    SMBException,
    SMBMachineException,
    SMBSocks5ConnectionError,
)
from aiosmb.wintypes.ntstatus import NTStatus


pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "status,value",
    [
        (NTStatus.SUCCESS, 0x00000000),
        (NTStatus.PENDING, 0x00000103),
        (NTStatus.OBJECT_NAME_EXISTS, 0x40000000),
        (NTStatus.BUFFER_OVERFLOW, 0x80000005),
        (NTStatus.NO_MORE_FILES, 0x80000006),
        (NTStatus.UNSUCCESSFUL, 0xC0000001),
        (NTStatus.ACCESS_DENIED, 0xC0000022),
        (NTStatus.OBJECT_NAME_NOT_FOUND, 0xC0000034),
        (NTStatus.SHARING_VIOLATION, 0xC0000043),
        (NTStatus.CONNECTION_ABORTED, 0xC0000241),
        (NTStatus.PIPE_NOT_AVAILABLE, 0xC00000AC),
    ],
)
def test_ntstatus_golden_values_and_lookup(status, value):
    assert status.value == value
    assert NTStatus(value) is status


def test_ntstatus_aliases_have_canonical_identity():
    assert NTStatus.WAIT_0 is NTStatus.SUCCESS
    assert NTStatus.WAIT_0.name == "SUCCESS"
    assert NTStatus.ABANDONED_WAIT_0 is NTStatus.ABANDONED
    assert NTStatus.ABANDONED_WAIT_0.name == "ABANDONED"


@pytest.mark.parametrize(
    "status,severity",
    [
        (NTStatus.SUCCESS, 0),
        (NTStatus.OBJECT_NAME_EXISTS, 1),
        (NTStatus.BUFFER_OVERFLOW, 2),
        (NTStatus.ACCESS_DENIED, 3),
    ],
)
def test_ntstatus_severity_bits(status, severity):
    assert status.value >> 30 == severity


def test_ntstatus_rejects_unknown_value():
    with pytest.raises(ValueError):
        NTStatus(0xDEADBEEF)


def test_smb_exception_formats_status_and_pretty_output():
    error = SMBException("open failed", NTStatus.ACCESS_DENIED)

    assert error.ntstatus is NTStatus.ACCESS_DENIED
    assert error.args == ("open failed Status: NTStatus.ACCESS_DENIED",)
    assert str(error) == "open failed Status: NTStatus.ACCESS_DENIED"
    assert error.pprint() == "ACCESS_DENIED [0xc0000022]"


def test_smb_exception_without_status_has_stable_fallback():
    error = SMBException("local failure")

    assert error.ntstatus is None
    assert str(error) == "local failure Status: None"
    assert error.pprint() == "Generic SMBException, missing NTSTATUS code."


def test_connection_terminated_carries_ntstatus_and_error_code():
    default = SMBConnectionTerminated()
    custom = SMBConnectionTerminated("peer closed")

    assert default.ntstatus is NTStatus.CONNECTION_ABORTED
    assert default.error_code is NTStatus.CONNECTION_ABORTED
    assert default.pprint() == "CONNECTION_ABORTED [0xc0000241]"
    assert str(default) == "ConnectionTerminated Status: NTStatus.CONNECTION_ABORTED"
    assert str(custom) == "peer closed Status: NTStatus.CONNECTION_ABORTED"


@pytest.mark.parametrize(
    "exception_type,default_message",
    [
        (SMBConnectionNetworkTerminated, "ConnectionTerminated"),
        (SMBConnectionTimeoutException, "ConnectionTimeout"),
        (SMBConnectionRefusedException, "ConnectionRefused"),
    ],
)
def test_network_exception_defaults_are_deterministic(
    exception_type, default_message
):
    error = exception_type()

    assert error.ntstatus == -1
    assert str(error) == "{} Status: -1".format(default_message)


def test_simple_exception_subclasses_retain_base_contracts():
    access_denied = SMBCreateAccessDenied("denied", NTStatus.ACCESS_DENIED)
    machine = SMBMachineException("machine state")
    socks = SMBSocks5ConnectionError("proxy refused")

    assert access_denied.pprint() == "ACCESS_DENIED [0xc0000022]"
    assert str(machine) == "machine state"
    assert str(socks) == "proxy refused"


@pytest.mark.xfail(
    strict=True,
    reason="KF-0311: network exception pprint crashes on its integer sentinel",
)
def test_network_exception_pretty_print_is_safe():
    rendered = SMBConnectionTimeoutException().pprint()

    assert rendered == "ConnectionTimeout [unavailable]"
