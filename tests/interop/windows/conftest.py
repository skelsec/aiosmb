"""Fixtures and report redaction for opt-in Windows interoperability."""

import asyncio
import os
from pathlib import Path
from typing import Any, List, Optional

import pytest

from ._lab import (
    EXAMPLE_PROFILE,
    collection_target_ids,
    discover_target,
    load_profile,
    require_runtime_capability,
    sanitize_text,
    sensitive_values,
)


def pytest_generate_tests(metafunc: pytest.Metafunc) -> None:
    if "windows_target" not in metafunc.fixturenames:
        return
    target_ids = collection_target_ids()
    metafunc.parametrize(
        "windows_target",
        target_ids,
        indirect=True,
        scope="session",
        ids=[target_id or "no-active-profile" for target_id in target_ids],
    )


@pytest.fixture(scope="session")
def windows_profile(request: pytest.FixtureRequest):
    if not request.config.getoption("--run-windows"):
        pytest.skip("requires explicit --run-windows opt-in")
    return load_profile()


@pytest.fixture(scope="session")
def windows_target(request: pytest.FixtureRequest, windows_profile):
    target_id: Optional[str] = request.param
    if target_id is None:
        pytest.skip("no active Windows target profile")
    return windows_profile.targets[target_id]


@pytest.fixture(scope="session")
def windows_metadata(windows_target):
    return asyncio.run(discover_target(windows_target))


@pytest.fixture(scope="session")
def windows_user_target(windows_target, windows_metadata):
    windows_target.require_declared_capability("authenticated_smb")
    require_runtime_capability(windows_metadata, "modern_smb")
    if windows_metadata.get("probe_only") is True:
        pytest.skip("SMB1-era targets remain probe-only")
    if not windows_target.profile.active:
        pytest.skip(
            "authenticated tests require an active ignored profile.local.yml"
        )
    return windows_target


@pytest.fixture(scope="session")
def windows_privileged_target(request, windows_target, windows_metadata):
    if not request.config.getoption("--run-privileged"):
        pytest.skip("requires explicit --run-privileged opt-in")
    require_runtime_capability(windows_metadata, "modern_smb")
    if not windows_target.profile.active:
        pytest.skip(
            "privileged tests require an active ignored profile.local.yml"
        )
    return windows_target


@pytest.fixture(scope="session")
def windows_destructive_target(request, windows_target, windows_metadata):
    if not request.config.getoption("--run-destructive"):
        pytest.skip("requires explicit --run-destructive opt-in")
    require_runtime_capability(windows_metadata, "modern_smb")
    if not windows_target.profile.active:
        pytest.skip(
            "destructive tests require an active ignored profile.local.yml"
        )
    return windows_target


def _report_redaction_values() -> List[str]:
    configured = Path(
        os.environ.get("AIOSMB_WINDOWS_PROFILE", str(EXAMPLE_PROFILE))
    ).expanduser()
    if not configured.is_file():
        configured = EXAMPLE_PROFILE
    try:
        return sensitive_values(load_profile(configured))
    except BaseException:
        return []


@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo[Any]):
    outcome = yield
    report = outcome.get_result()
    values = _report_redaction_values()
    if report.longrepr:
        if isinstance(report.longrepr, tuple):
            report.longrepr = tuple(
                sanitize_text(value, values)
                if isinstance(value, str)
                else value
                for value in report.longrepr
            )
        else:
            report.longrepr = sanitize_text(report.longreprtext, values)
    report.sections = [
        (name, sanitize_text(content, values))
        for name, content in report.sections
    ]
