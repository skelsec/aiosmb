"""Contracts for the root one-command test runner."""

import os
import subprocess
from pathlib import Path

import pytest


pytestmark = pytest.mark.component
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
TEST_RUNNER = REPOSITORY_ROOT / "test.sh"


def _run(*arguments: str) -> subprocess.CompletedProcess:
    environment = os.environ.copy()
    environment.pop("AIOSMB_CONFIRM_DESTRUCTIVE", None)
    return subprocess.run(
        [str(TEST_RUNNER), *arguments],
        cwd=str(REPOSITORY_ROOT),
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        check=False,
    )


def test_runner_is_executable_and_has_valid_bash_syntax() -> None:
    assert TEST_RUNNER.is_file()
    assert os.access(str(TEST_RUNNER), os.X_OK)

    completed = subprocess.run(
        ["bash", "-n", str(TEST_RUNNER)],
        cwd=str(REPOSITORY_ROOT),
        check=False,
    )
    assert completed.returncode == 0


def test_runner_help_documents_self_contained_and_live_modes() -> None:
    completed = _run("--help")

    assert completed.returncode == 0
    assert "baseline" in completed.stdout
    assert "full" in completed.stdout
    assert "samba" in completed.stdout
    assert "goad-discovery" in completed.stdout
    assert "goad-readonly" in completed.stdout
    assert "goad-privileged" in completed.stdout
    assert "goad-full" in completed.stdout
    assert "destructive" in completed.stdout
    assert "removed on success" in completed.stdout


@pytest.mark.parametrize("mode", ["destructive", "goad-full"])
def test_destructive_modes_require_a_second_explicit_confirmation(mode: str) -> None:
    profile = REPOSITORY_ROOT / "tests" / "interop" / "windows" / "goad.example.yml"
    completed = _run(
        mode,
        "--windows-profile",
        str(profile),
    )

    assert completed.returncode == 2
    assert "AIOSMB_CONFIRM_DESTRUCTIVE=YES" in completed.stderr
    assert "Creating isolated test environment" not in completed.stdout


def test_goad_full_enables_every_non_quarantined_gate() -> None:
    runner = TEST_RUNNER.read_text(encoding="utf-8")

    assert "run_goad_group all" in runner
    assert "--privileged" in runner
    assert "--destructive" in runner
    assert "--pytest-arg=--run-slow" in runner
    assert "--pytest-arg=compression" in runner
