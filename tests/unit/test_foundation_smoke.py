"""Offline smoke tests for package and test-suite foundations."""

import asyncio
import importlib
import re
import sys
import warnings
from importlib import metadata
from pathlib import Path

import pytest
import yaml
from packaging.requirements import Requirement


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
EXPECTED_ENTRY_POINTS = {
    "asmbclient": "aiosmb.examples.smbclient:main",
    "asmbshareenum": "aiosmb.examples.smbshareenum:main",
    "asmbgetfile": "aiosmb.examples.smbgetfile:main",
    "asmbcertreq": "aiosmb.examples.smbcertreq:main",
    "asmbscanner": "aiosmb.examples.scanners.__main__:main",
    "aiosmb-server": "aiosmb.examples.smbserver:main",
}
EXPECTED_MARKERS = {
    "unit",
    "fake_peer",
    "component",
    "samba",
    "windows",
    "slow",
    "destructive",
    "privileged",
    "quarantine",
    "capability",
}
LEGACY_TEST_FILES = {
    "aiosmb/tests/negback.py",
    "aiosmb/tests/ntlm/ntlmv1.py",
    "aiosmb/tests/ntlm/ntlmv1ess.py",
    "aiosmb/tests/ntlm/ntlmv2.py",
    "aiosmb/tests/ntlm/structs_test.py",
}


@pytest.mark.unit
def test_package_and_connection_import() -> None:
    package = importlib.import_module("aiosmb")
    connection = importlib.import_module("aiosmb.connection")

    assert package.__name__ == "aiosmb"
    assert connection.SMBConnection.__module__ == "aiosmb.connection"


@pytest.mark.unit
def test_suite_uses_supported_python() -> None:
    assert sys.version_info >= (3, 8), "the pytest suite requires Python 3.8+"


@pytest.mark.unit
def test_version_matches_installed_distribution() -> None:
    from aiosmb._version import __version__

    assert re.fullmatch(r"[0-9]+(?:\.[0-9]+)+(?:[A-Za-z0-9._+-]*)?", __version__)
    assert metadata.version("aiosmb") == __version__


@pytest.mark.unit
@pytest.mark.parametrize("name,target", sorted(EXPECTED_ENTRY_POINTS.items()))
def test_console_entry_point_loads(name: str, target: str) -> None:
    if sys.version_info < (3, 9):
        pytest.skip("blocked by KF-0107")
    distribution = metadata.distribution("aiosmb")
    entry_points = {
        entry_point.name: entry_point
        for entry_point in distribution.entry_points
        if entry_point.group == "console_scripts"
    }

    assert name in entry_points
    assert entry_points[name].value == target
    if name == "asmbcertreq":
        pytest.skip("blocked by KF-0002: msldap is not a declared dependency")
    assert callable(entry_points[name].load())


@pytest.mark.unit
@pytest.mark.xfail(
    strict=True,
    reason="KF-0002: asmbcertreq imports the undeclared msldap dependency",
)
def test_asmbcertreq_declares_msldap_runtime_dependency() -> None:
    requirements = metadata.distribution("aiosmb").requires or []
    requirement_names = {Requirement(value).name.lower() for value in requirements}

    assert "msldap" in requirement_names


@pytest.mark.unit
def test_collection_scope_and_markers(pytestconfig: pytest.Config) -> None:
    assert pytestconfig.getini("testpaths") == ["tests"]
    assert "--strict-markers" in pytestconfig.getini("addopts")
    assert "--randomly-seed=20240814" in pytestconfig.getini("addopts")
    assert pytestconfig.getini("asyncio_mode") == "strict"
    assert float(pytestconfig.getini("timeout")) == 30

    configured_markers = {
        marker.split(":", 1)[0].split("(", 1)[0]
        for marker in pytestconfig.getini("markers")
    }
    assert EXPECTED_MARKERS <= configured_markers


@pytest.mark.unit
def test_legacy_test_vectors_are_preserved() -> None:
    missing = {
        relative_path
        for relative_path in LEGACY_TEST_FILES
        if not (REPOSITORY_ROOT / relative_path).is_file()
    }
    assert not missing


@pytest.mark.unit
def test_known_failure_registry_schema_and_example() -> None:
    registry_path = REPOSITORY_ROOT / "tests" / "known_failures.yml"
    registry = yaml.safe_load(registry_path.read_text(encoding="utf-8"))

    assert registry["schema_version"] == 1
    assert isinstance(registry["known_failures"], list)

    required = set(registry["schema"]["entry_required"])
    assert required <= set(registry["example_entry"])
    seen_ids = set()
    for entry in registry["known_failures"]:
        assert required <= set(entry)
        assert re.fullmatch(registry["schema"]["id_pattern"], entry["id"])
        assert entry["id"] not in seen_ids
        assert entry["status"] in registry["schema"]["status_values"]
        assert (
            entry["classification"]
            in registry["schema"]["classification_values"]
        )
        seen_ids.add(entry["id"])


@pytest.mark.unit
@pytest.mark.xfail(
    strict=True,
    reason="KF-0001: smbreg help text contains invalid escape sequences",
)
def test_smbreg_source_compiles_without_escape_warnings() -> None:
    source_path = REPOSITORY_ROOT / "aiosmb" / "examples" / "smbreg.py"
    source = source_path.read_text(encoding="utf-8")

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        compile(source, str(source_path), "exec")

    invalid_escapes = [
        warning
        for warning in caught
        if "invalid escape sequence" in str(warning.message)
    ]
    assert not invalid_escapes


@pytest.mark.unit
@pytest.mark.asyncio
async def test_strict_asyncio_smoke() -> None:
    await asyncio.sleep(0)
