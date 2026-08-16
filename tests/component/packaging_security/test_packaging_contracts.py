"""Installed metadata, package discovery, and console entry-point contracts."""

import re
import sys
from importlib import metadata
from pathlib import Path, PurePosixPath
from typing import Dict, Set

import pytest
from packaging.specifiers import SpecifierSet
from packaging.version import Version
from setuptools import find_packages

from aiosmb._version import __banner__, __version__


pytestmark = pytest.mark.component

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
EXPECTED_ENTRY_POINTS: Dict[str, str] = {
    "aiosmb-server": "aiosmb.examples.smbserver:main",
    "asmbcertreq": "aiosmb.examples.smbcertreq:main",
    "asmbclient": "aiosmb.examples.smbclient:main",
    "asmbgetfile": "aiosmb.examples.smbgetfile:main",
    "asmbscanner": "aiosmb.examples.scanners.__main__:main",
    "asmbshareenum": "aiosmb.examples.smbshareenum:main",
}
EXPECTED_RUNTIME_REQUIREMENTS = {
    "aiosmb": {
        "asn1crypto",
        "asyauth",
        "asysocks",
        "colorama",
        "cryptography",
        "prompt-toolkit",
        "six",
        "tqdm",
        "unicrypto",
        "wcwidth",
        "winacl",
    }
}


def _distribution() -> metadata.Distribution:
    return metadata.distribution("aiosmb")


def _requirement_name(requirement: str) -> str:
    return re.split(r"[\s<>=!~;\[]", requirement, maxsplit=1)[0].lower()


def test_installed_distribution_metadata_matches_project_contract() -> None:
    distribution = _distribution()
    project_metadata = distribution.metadata
    requirements = distribution.requires or []

    assert project_metadata["Name"] == "aiosmb"
    assert project_metadata["Summary"] == (
        "Asynchronous SMB protocol implementation"
    )
    assert project_metadata["Home-page"] == "https://github.com/skelsec/aiosmb"
    assert project_metadata["License"] == (
        "Modified Apache Software License 1.1"
    )
    assert project_metadata["Author"] == "Tamas Jos"
    assert project_metadata["Author-email"] == "info@skelsecprojects.com"
    assert Version("3.8") in SpecifierSet(project_metadata["Requires-Python"])
    assert EXPECTED_RUNTIME_REQUIREMENTS["aiosmb"] <= {
        _requirement_name(item) for item in requirements
    }
    assert distribution.read_text("top_level.txt").split() == ["aiosmb"]


def test_declared_console_entry_points_match_installed_metadata() -> None:
    installed = {
        entry_point.name: entry_point.value
        for entry_point in _distribution().entry_points
        if entry_point.group == "console_scripts"
    }

    assert installed == EXPECTED_ENTRY_POINTS


@pytest.mark.parametrize(
    "name,target",
    [
        pytest.param(
            name,
            target,
            id=name,
        )
        for name, target in sorted(EXPECTED_ENTRY_POINTS.items())
    ],
)
def test_each_declared_console_entry_point_loads(
    name: str, target: str
) -> None:
    if sys.version_info < (3, 9):
        pytest.skip("blocked by KF-0107")
    entry_points = {
        entry_point.name: entry_point
        for entry_point in _distribution().entry_points
        if entry_point.group == "console_scripts"
    }

    assert entry_points[name].value == target
    if name == "asmbcertreq":
        pytest.skip("blocked by KF-0002: msldap is not a declared dependency")
    assert callable(entry_points[name].load())


def test_setuptools_discovers_every_source_package_and_no_test_package() -> None:
    expected = {
        path.parent.relative_to(REPOSITORY_ROOT).as_posix().replace("/", ".")
        for path in (REPOSITORY_ROOT / "aiosmb").rglob("__init__.py")
    }
    discovered = set(
        find_packages(
            where=str(REPOSITORY_ROOT),
            exclude=("tests", "tests.*"),
        )
    )

    assert discovered == expected
    assert all(
        package != "tests" and not package.startswith("tests.")
        for package in discovered
    )


def test_installed_file_manifest_covers_discovered_python_modules() -> None:
    discovered = set(
        find_packages(
            where=str(REPOSITORY_ROOT),
            exclude=("tests", "tests.*"),
        )
    )
    source_modules: Set[PurePosixPath] = set()
    for package in discovered:
        package_path = REPOSITORY_ROOT.joinpath(*package.split("."))
        source_modules.update(
            PurePosixPath(path.relative_to(REPOSITORY_ROOT).as_posix())
            for path in package_path.glob("*.py")
        )

    recorded_modules = {
        PurePosixPath(str(path))
        for path in (_distribution().files or ())
        if str(path).startswith("aiosmb/") and str(path).endswith(".py")
    }

    assert recorded_modules == source_modules
    assert all("__pycache__" not in path.parts for path in recorded_modules)
    assert all(path.parts[:2] != ("aiosmb", "tests") for path in recorded_modules)


def test_version_source_metadata_and_banner_are_consistent() -> None:
    setup_source = (REPOSITORY_ROOT / "setup.py").read_text(encoding="utf-8")
    setup_version_file = re.search(
        r'^VERSIONFILE\s*=\s*["\']([^"\']+)["\']',
        setup_source,
        re.MULTILINE,
    )

    assert setup_version_file is not None
    assert setup_version_file.group(1) == "aiosmb/_version.py"
    assert metadata.version("aiosmb") == __version__
    assert re.fullmatch(
        r"[0-9]+(?:\.[0-9]+)+(?:[A-Za-z0-9._+-]*)?", __version__
    )
    assert "# aiosmb {} ".format(__version__) in __banner__
    assert __banner__.count(__version__) == 1
    assert "%s" not in __banner__
