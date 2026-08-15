"""Secret redaction and exception-chain contracts at public boundaries."""

import logging
import sys
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Tuple

import pytest

if sys.version_info < (3, 9):
    pytest.skip("blocked by KF-0107", allow_module_level=True)

from aiosmb.commons.connection.factory import SMBConnectionFactory
from aiosmb.commons.interfaces import machine as machine_module
from aiosmb.commons.interfaces.machine import SMBMachine
from aiosmb.connection import SMBConnection
from aiosmb.examples.smbclient import SMBClient


pytestmark = pytest.mark.component

SYNTHETIC_SECRET = "SYNTHETIC_ONLY_8f41c66a_PASSWORD"
SYNTHETIC_URL = (
    "smb+ntlm-password://EXAMPLE\\alice:"
    + SYNTHETIC_SECRET
    + "@server.invalid/share"
)


def _factory_with_synthetic_secret() -> SMBConnectionFactory:
    return SMBConnectionFactory.from_url(SYNTHETIC_URL)


def test_connection_factory_repr_does_not_expose_credentials() -> None:
    assert SYNTHETIC_SECRET not in repr(_factory_with_synthetic_secret())


@pytest.mark.xfail(
    strict=True,
    reason="KF-0660: connection factory string rendering exposes credentials",
)
def test_connection_factory_string_does_not_expose_credentials() -> None:
    assert SYNTHETIC_SECRET not in str(_factory_with_synthetic_secret())


def test_url_parse_errors_do_not_echo_userinfo() -> None:
    invalid_url = SYNTHETIC_URL.replace(
        "@server.invalid/", "@server.invalid:not-a-port/"
    )

    with pytest.raises(ValueError) as exc_info:
        SMBConnectionFactory.from_url(invalid_url)

    assert SYNTHETIC_SECRET not in str(exc_info.value)
    assert "not-a-port" in str(exc_info.value)


class _FailingAuthentication:
    def __init__(self, error: Exception) -> None:
        self.error = error

    async def authenticate(
        self, *args: Any, **kwargs: Any
    ) -> Tuple[None, None, Exception]:
        return None, None, self.error


class _AuthenticationTarget:
    def to_target_string(self) -> str:
        return "cifs/server.invalid@EXAMPLE"


async def _run_failing_session_setup(
    error: Exception,
) -> Tuple[bool, Exception]:
    connection = object.__new__(SMBConnection)
    connection.gssapi = _FailingAuthentication(error)
    connection.target = _AuthenticationTarget()
    return await connection.session_setup()


@pytest.mark.asyncio
@pytest.mark.xfail(
    strict=True,
    reason="KF-0661: Kerberos preauthentication wrapping drops explicit cause",
)
async def test_authentication_wrapper_preserves_original_exception_cause() -> None:
    original = RuntimeError("Preauth rejected by synthetic peer")

    success, error = await _run_failing_session_setup(original)

    assert success is False
    assert error.__cause__ is original


@pytest.mark.asyncio
@pytest.mark.xfail(
    strict=True,
    reason="KF-0662: authentication errors expose secret-bearing cause text",
)
async def test_authentication_error_rendering_redacts_secret_text() -> None:
    original = RuntimeError("Preauth rejected for " + SYNTHETIC_SECRET)

    success, error = await _run_failing_session_setup(original)

    assert success is False
    assert SYNTHETIC_SECRET not in str(error)


def _diagnostic_output(capsys: Any, caplog: Any) -> str:
    captured = capsys.readouterr()
    return captured.out + captured.err + caplog.text


@pytest.mark.xfail(
    strict=True,
    reason="KF-0663: CLI exception diagnostics expose caller secret arguments",
)
def test_cli_exception_diagnostics_redact_caller_arguments(
    capsys: Any, caplog: Any
) -> None:
    caplog.set_level(logging.DEBUG, logger="aiosmb")

    def invoke(password: str) -> Tuple[bool, Exception]:
        return SMBClient.handle_exception(
            object(), RuntimeError("synthetic login rejected")
        )

    success, error = invoke(SYNTHETIC_SECRET)

    assert success is False
    assert isinstance(error, RuntimeError)
    assert SYNTHETIC_SECRET not in _diagnostic_output(capsys, caplog)


@pytest.mark.xfail(
    strict=True,
    reason="KF-0664: CLI exception diagnostics expose secret-bearing errors",
)
def test_cli_exception_diagnostics_redact_error_messages(
    capsys: Any, caplog: Any
) -> None:
    caplog.set_level(logging.DEBUG, logger="aiosmb")
    error = RuntimeError(
        "connection failed for smb://alice:"
        + SYNTHETIC_SECRET
        + "@server.invalid"
    )

    success, returned_error = SMBClient.handle_exception(object(), error)

    assert success is False
    assert returned_error is error
    assert SYNTHETIC_SECRET not in _diagnostic_output(capsys, caplog)


class _SyntheticSecretRecord:
    def __str__(self) -> str:
        return SYNTHETIC_SECRET

    def __repr__(self) -> str:
        return "<SyntheticSecretRecord {}>".format(SYNTHETIC_SECRET)


class _FakeSamr:
    async def get_domain_sid(self, domain: str) -> Tuple[str, None]:
        return "S-1-5-21-100", None

    async def open_domain(self, sid: str) -> Tuple[str, None]:
        return "domain-handle", None

    async def list_domain_users(
        self, handle: str
    ) -> AsyncIterator[Tuple[str, str, None]]:
        yield "alice", "S-1-5-21-100-1100", None


class _FakeDrsuapi:
    def __init__(self, record: _SyntheticSecretRecord) -> None:
        self.record = record

    async def get_user_secrets(
        self, user_sid: str
    ) -> Tuple[_SyntheticSecretRecord, None]:
        return self.record, None


@pytest.mark.asyncio
@pytest.mark.xfail(
    strict=True,
    reason="KF-0665: DCSync debug logging renders replicated secrets",
)
async def test_dcsync_logging_does_not_render_secret_records(
    monkeypatch: Any, caplog: Any
) -> None:
    record = _SyntheticSecretRecord()

    @asynccontextmanager
    async def fake_samr(*args: Any, **kwargs: Any) -> AsyncIterator[_FakeSamr]:
        yield _FakeSamr()

    @asynccontextmanager
    async def fake_drsuapi(
        *args: Any, **kwargs: Any
    ) -> AsyncIterator[_FakeDrsuapi]:
        yield _FakeDrsuapi(record)

    monkeypatch.setattr(machine_module, "samrrpc_from_smb", fake_samr)
    monkeypatch.setattr(machine_module, "drsuapirpc_from_smb", fake_drsuapi)
    caplog.set_level(logging.DEBUG, logger="aiosmb")
    machine = SMBMachine(connection=object())

    observed = [
        item
        async for item in machine.dcsync(target_domain="EXAMPLE")
    ]

    assert observed == [(record, None)]
    assert SYNTHETIC_SECRET not in caplog.text
