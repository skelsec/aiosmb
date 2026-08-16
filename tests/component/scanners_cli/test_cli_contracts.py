"""Argument, help, and exit contracts for offline console paths."""

import asyncio
import importlib
import subprocess
import sys
from pathlib import Path

import pytest


if sys.version_info < (3, 9):
    pytest.skip("blocked by KF-0107", allow_module_level=True)

pytestmark = pytest.mark.component
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


def run_module(module, *arguments):
    return subprocess.run(
        [sys.executable, "-m", module] + list(arguments),
        cwd=str(REPOSITORY_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        timeout=15,
        check=False,
    )


@pytest.mark.parametrize(
    "module,description",
    [
        ("aiosmb.examples.smbclient", "Interactive SMB client"),
        ("aiosmb.examples.smbshareenum", "SMB Share enumerator"),
        ("aiosmb.examples.smbgetfile", "SMB file downloader"),
        ("aiosmb.examples.scanners.__main__", "SMB Scanner"),
    ],
)
def test_console_module_help_exits_zero(module, description) -> None:
    completed = run_module(module, "--help")

    assert completed.returncode == 0
    assert "usage:" in completed.stdout
    assert description in completed.stdout
    assert completed.stderr == ""


@pytest.mark.parametrize(
    "module",
    [
        "aiosmb.examples.smbclient",
        "aiosmb.examples.smbgetfile",
        "aiosmb.examples.scanners.__main__",
    ],
)
def test_console_module_missing_required_arguments_exits_two(module) -> None:
    completed = run_module(module)

    assert completed.returncode == 2
    assert "usage:" in completed.stderr
    assert "error:" in completed.stderr


def test_scanner_subcommand_help_is_offline_and_documents_targets() -> None:
    completed = run_module("aiosmb.examples.scanners.__main__", "proto", "--help")

    assert completed.returncode == 0
    assert "targets" in completed.stdout
    assert "Hostname or IP address" in completed.stdout
    assert completed.stderr == ""


def test_encryption_scanner_help_documents_authenticated_url_and_targets() -> None:
    completed = run_module(
        "aiosmb.examples.scanners.__main__",
        "encryption",
        "--help",
    )

    assert completed.returncode == 0
    assert "url" in completed.stdout
    assert "Authenticated connection string" in completed.stdout
    assert "targets" in completed.stdout
    assert completed.stderr == ""


@pytest.mark.asyncio
async def test_encryption_scanner_dispatches_authenticated_factory(
    monkeypatch,
) -> None:
    module = importlib.import_module("aiosmb.examples.scanners.__main__")
    targetgen_module = importlib.import_module(
        "asysocks.unicomm.common.scanner.targetgen"
    )
    scanner_module = importlib.import_module(
        "asysocks.unicomm.common.scanner.scanner"
    )
    calls = {}

    class FakeConnectionFactory:
        @staticmethod
        def from_url(url):
            calls["url"] = url
            return "authenticated-factory"

    class FakeExecutor:
        def __init__(self, factory):
            calls["executor_factory"] = factory

    class FakeTargetGen:
        @classmethod
        def from_list(cls, targets):
            calls["targets"] = list(targets)
            return "target-generator"

    class FakeScanner:
        def __init__(
            self, name, executors, target_generators, worker_count, host_timeout
        ):
            calls["scanner"] = (
                name,
                executors,
                target_generators,
                worker_count,
                host_timeout,
            )

        async def scan_and_process(self, **kwargs):
            calls["processing"] = kwargs

    monkeypatch.setattr(module, "SMBConnectionFactory", FakeConnectionFactory)
    monkeypatch.setitem(
        module.smbscan_options,
        "encryption",
        (FakeExecutor, module.smbscan_options["encryption"][1]),
    )
    monkeypatch.setattr(targetgen_module, "UniTargetGen", FakeTargetGen)
    monkeypatch.setattr(scanner_module, "UniScanner", FakeScanner)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "asmbscanner",
            "--worker-count",
            "4",
            "--timeout",
            "9",
            "encryption",
            "smb3+ntlm-password://EXAMPLE\\alice:secret@placeholder",
            "files.example",
        ],
    )

    await module.amain()

    assert calls["url"] == (
        "smb3+ntlm-password://EXAMPLE\\alice:secret@placeholder"
    )
    assert calls["executor_factory"] == "authenticated-factory"
    assert calls["targets"] == ["files.example"]
    assert calls["scanner"][3:] == (4, 9)


def test_getfile_main_dispatches_url_output_and_progress(monkeypatch) -> None:
    module = importlib.import_module("aiosmb.examples.smbgetfile")
    calls = []

    async def fake_amain(url, output, progress=True):
        calls.append((url, output, progress))

    monkeypatch.setattr(module, "amain", fake_amain)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "asmbgetfile",
            "--progress",
            "--out-file",
            "local.bin",
            "smb://files.example/share/remote.bin",
        ],
    )

    module.main()

    assert calls == [
        ("smb://files.example/share/remote.bin", "local.bin", True)
    ]


@pytest.mark.xfail(
    strict=True,
    reason="KF-0645: getfile CLI enables progress when the flag is absent",
)
def test_getfile_main_leaves_progress_disabled_by_default(monkeypatch) -> None:
    module = importlib.import_module("aiosmb.examples.smbgetfile")
    calls = []

    async def fake_amain(url, output, progress=True):
        calls.append((url, output, progress))

    monkeypatch.setattr(module, "amain", fake_amain)
    monkeypatch.setattr(
        sys,
        "argv",
        ["asmbgetfile", "smb://files.example/share/remote.bin"],
    )

    module.main()

    assert calls == [
        ("smb://files.example/share/remote.bin", None, False)
    ]


@pytest.mark.asyncio
@pytest.mark.xfail(
    strict=True,
    reason="KF-0646: smbget reads an argparse destination that was never defined",
)
async def test_smbget_dispatches_the_parsed_url_without_network(monkeypatch) -> None:
    module = importlib.import_module("aiosmb.examples.smbget")
    created = []

    class FakeGet:
        def __init__(self, url, show_progress=False):
            created.append((url, show_progress))
            self.target_gens = []

        async def run(self):
            return True, None

    monkeypatch.setattr(module, "SMBGET", FakeGet)
    monkeypatch.setattr(
        sys,
        "argv",
        ["smbget", "smb://files.example", r"\\files.example\share\a.txt"],
    )

    await module.amain()

    assert created == [("smb://files.example", False)]


@pytest.mark.asyncio
@pytest.mark.xfail(
    strict=True,
    reason=(
        "KF-0647: smbgetfilezip reads an argparse destination that was never "
        "defined"
    ),
)
async def test_smbgetfilezip_dispatches_the_parsed_url_without_network(
    monkeypatch,
) -> None:
    module = importlib.import_module("aiosmb.examples.smbgetfilezip")
    created = []

    class FakeGet:
        def __init__(self, url, show_progress=False):
            created.append((url, show_progress))
            self.target_gens = []

        async def run(self):
            return True, None

    monkeypatch.setattr(module, "SMBGET", FakeGet)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "smbgetfilezip",
            "smb://files.example",
            r"\\files.example\share\a.txt",
        ],
    )

    await module.amain()

    assert created == [("smb://files.example", False)]


@pytest.mark.asyncio
@pytest.mark.xfail(
    strict=True,
    reason="KF-0648: scanner no-progress flag is passed with inverted meaning",
)
async def test_scanner_progress_is_enabled_by_default(monkeypatch) -> None:
    module = importlib.import_module("aiosmb.examples.scanners.__main__")
    targetgen_module = importlib.import_module(
        "asysocks.unicomm.common.scanner.targetgen"
    )
    scanner_module = importlib.import_module(
        "asysocks.unicomm.common.scanner.scanner"
    )
    calls = {}

    class FakeConnectionFactory:
        @staticmethod
        def create_dummy():
            return "factory"

    class FakeExecutor:
        def __init__(self, factory):
            calls["executor_factory"] = factory

    class FakeTargetGen:
        @classmethod
        def from_list(cls, targets):
            calls["targets"] = list(targets)
            return "target-generator"

    class FakeScanner:
        def __init__(
            self, name, executors, target_generators, worker_count, host_timeout
        ):
            calls["scanner"] = (
                name,
                executors,
                target_generators,
                worker_count,
                host_timeout,
            )

        async def scan_and_process(self, **kwargs):
            calls["processing"] = kwargs

    monkeypatch.setattr(module, "SMBConnectionFactory", FakeConnectionFactory)
    monkeypatch.setitem(
        module.smbscan_options,
        "finger",
        (FakeExecutor, module.smbscan_options["finger"][1]),
    )
    monkeypatch.setattr(targetgen_module, "UniTargetGen", FakeTargetGen)
    monkeypatch.setattr(scanner_module, "UniScanner", FakeScanner)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "asmbscanner",
            "--worker-count",
            "3",
            "--timeout",
            "7",
            "finger",
            "files.example",
        ],
    )

    await module.amain()

    assert calls["executor_factory"] == "factory"
    assert calls["targets"] == ["files.example"]
    assert calls["scanner"][3:] == (3, 7)
    assert calls["processing"]["progress"] is True
