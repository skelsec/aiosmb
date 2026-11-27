#!/usr/bin/env python3
"""Controller for secret-free discovery and explicitly gated Windows tests."""

import argparse
import asyncio
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence

try:
    from ._lab import (
        CREDENTIAL_TIERS,
        DEFAULT_PROFILE,
        EXAMPLE_PROFILE,
        PROFILE_ENVIRONMENT,
        TARGETS_ENVIRONMENT,
        discover_profile,
        load_profile,
        sanitize_text,
        sensitive_values,
    )
except ImportError:
    from _lab import (  # type: ignore
        CREDENTIAL_TIERS,
        DEFAULT_PROFILE,
        EXAMPLE_PROFILE,
        PROFILE_ENVIRONMENT,
        TARGETS_ENVIRONMENT,
        discover_profile,
        load_profile,
        sanitize_text,
        sensitive_values,
    )


WINDOWS_DIRECTORY = Path(__file__).resolve().parent
REPOSITORY_ROOT = WINDOWS_DIRECTORY.parents[2]
DEFAULT_ARTIFACT_DIRECTORY = WINDOWS_DIRECTORY / "artifacts.local"
TEST_GROUPS = {
    "all": [WINDOWS_DIRECTORY],
    "discovery": [WINDOWS_DIRECTORY / "test_inventory_and_discovery.py"],
    "user": [WINDOWS_DIRECTORY / "test_user_smb.py"],
    "rpc": [WINDOWS_DIRECTORY / "test_rpc_readonly.py"],
    "privileged": [WINDOWS_DIRECTORY / "test_privileged_readonly.py"],
    "destructive": [
        WINDOWS_DIRECTORY / "test_destructive.py",
        WINDOWS_DIRECTORY / "test_compression.py",
    ],
}
TEXT_ARTIFACT_SUFFIXES = {".json", ".log", ".txt", ".xml", ".yml", ".yaml"}


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _configure_targets(targets: Sequence[str]) -> None:
    if targets:
        os.environ[TARGETS_ENVIRONMENT] = ",".join(targets)
    else:
        os.environ.pop(TARGETS_ENVIRONMENT, None)


def _write_json(path: Path, document: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _authentication_not_executed() -> Mapping[str, Any]:
    return {
        "attempted": False,
        "reason": "unauthenticated discovery never resolves credential environments",
        "tiers": {
            tier: "not_executed_no_secret_injection"
            for tier in CREDENTIAL_TIERS
        },
    }


def run_discovery(arguments: argparse.Namespace) -> int:
    profile_path = Path(arguments.profile).expanduser().resolve()
    if not profile_path.is_file():
        raise SystemExit(
            "Windows discovery profile does not exist: {}".format(profile_path)
        )
    _configure_targets(arguments.target)
    profile = load_profile(profile_path)
    results = asyncio.run(discover_profile(profile))
    document = {
        "schema_version": 1,
        "generated_at": _utc_timestamp(),
        "mode": "unauthenticated_reachability_dialect_fingerprint",
        "profile": profile.name,
        "lab_kind": profile.lab_kind,
        "authentication": _authentication_not_executed(),
        "targets": results,
    }
    artifact_directory = Path(arguments.artifact_dir).expanduser().resolve()
    output_path = artifact_directory / "discovery.json"
    _write_json(output_path, document)
    print(json.dumps(document, indent=2, sort_keys=True))
    print("wrote redacted discovery artifact: {}".format(output_path))
    return 0 if all(item["all_expectations_met"] for item in results) else 1


def _credential_status(profile) -> Mapping[str, Any]:
    statuses: Dict[str, Any] = {}
    for tier_name, tier in profile.credential_tiers.items():
        missing = [
            name
            for name in tier.environment_names
            if not os.environ.get(name)
        ]
        statuses[tier_name] = {
            "available": not missing,
            "missing_environment": missing,
        }
    return statuses


def _redact_artifacts(directory: Path, values: Iterable[str]) -> None:
    if not directory.is_dir():
        return
    for path in directory.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in TEXT_ARTIFACT_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        path.write_text(sanitize_text(text, values), encoding="utf-8")


def _validate_test_request(
    arguments: argparse.Namespace, profile
) -> None:
    if arguments.group == "privileged" and not arguments.privileged:
        raise SystemExit(
            "--group privileged requires the separate --privileged gate"
        )
    if arguments.group == "destructive" and not arguments.destructive:
        raise SystemExit(
            "--group destructive requires the separate --destructive gate"
        )
    if (
        arguments.group != "discovery"
        and not arguments.collect_only
        and not profile.active
    ):
        raise SystemExit(
            "authenticated test groups require an ignored active "
            "profile.local.yml"
        )


def run_tests(arguments: argparse.Namespace) -> int:
    profile_path = Path(arguments.profile).expanduser().resolve()
    if not profile_path.is_file():
        raise SystemExit(
            "Windows test profile does not exist: {}".format(profile_path)
        )
    _configure_targets(arguments.target)
    os.environ[PROFILE_ENVIRONMENT] = str(profile_path)
    profile = load_profile(profile_path)
    _validate_test_request(arguments, profile)

    artifact_directory = Path(arguments.artifact_dir).expanduser().resolve()
    artifact_directory.mkdir(parents=True, exist_ok=True)
    junit_path = artifact_directory / "junit.xml"
    auth_status_path = artifact_directory / "authentication-status.json"
    _write_json(
        auth_status_path,
        {
            "schema_version": 1,
            "generated_at": _utc_timestamp(),
            "profile": profile.name,
            "test_group": arguments.group,
            "credential_tiers": _credential_status(profile),
        },
    )

    command: List[str] = [
        sys.executable,
        "-m",
        "pytest",
        *[str(path) for path in TEST_GROUPS[arguments.group]],
        "--run-windows",
        "--junitxml={}".format(junit_path),
    ]
    if arguments.privileged:
        command.append("--run-privileged")
    if arguments.destructive:
        command.append("--run-destructive")
    if arguments.collect_only:
        command.append("--collect-only")
    command.extend(arguments.pytest_arg)

    completed = subprocess.run(
        command,
        cwd=str(REPOSITORY_ROOT),
        env=os.environ.copy(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        check=False,
    )
    values = sensitive_values(profile)
    stdout = sanitize_text(completed.stdout, values)
    stderr = sanitize_text(completed.stderr, values)
    (artifact_directory / "pytest.stdout.txt").write_text(
        stdout, encoding="utf-8"
    )
    (artifact_directory / "pytest.stderr.txt").write_text(
        stderr, encoding="utf-8"
    )
    _redact_artifacts(artifact_directory, values)
    if stdout:
        print(stdout, end="" if stdout.endswith("\n") else "\n")
    if stderr:
        print(stderr, file=sys.stderr, end="" if stderr.endswith("\n") else "\n")
    print("wrote redacted test artifacts: {}".format(artifact_directory))
    return completed.returncode


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Discover the GOAD inventory without credentials or run explicitly "
            "gated Windows interoperability tests."
        )
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    discovery = subparsers.add_parser(
        "discover",
        help="run reachability, dialect, signing, and NTLM fingerprint probes",
    )
    discovery.add_argument(
        "--profile", default=str(EXAMPLE_PROFILE), help="secret-free manifest"
    )
    discovery.add_argument(
        "--target", action="append", default=[], help="target id; repeatable"
    )
    discovery.add_argument(
        "--artifact-dir",
        default=str(DEFAULT_ARTIFACT_DIRECTORY),
        help="ignored redacted artifact directory",
    )
    discovery.set_defaults(handler=run_discovery)

    tests = subparsers.add_parser(
        "test", help="select and run an explicitly gated test group"
    )
    tests.add_argument(
        "--profile", default=str(DEFAULT_PROFILE), help="ignored active profile"
    )
    tests.add_argument(
        "--target", action="append", default=[], help="target id; repeatable"
    )
    tests.add_argument(
        "--group", choices=sorted(TEST_GROUPS), default="all"
    )
    tests.add_argument(
        "--privileged",
        action="store_true",
        help="pass the separate --run-privileged pytest gate",
    )
    tests.add_argument(
        "--destructive",
        action="store_true",
        help="pass the separate --run-destructive pytest gate",
    )
    tests.add_argument("--collect-only", action="store_true")
    tests.add_argument(
        "--pytest-arg",
        action="append",
        default=[],
        help="additional pytest argument; repeatable",
    )
    tests.add_argument(
        "--artifact-dir",
        default=str(DEFAULT_ARTIFACT_DIRECTORY),
        help="ignored redacted artifact directory",
    )
    tests.set_defaults(handler=run_tests)
    return parser


def main(argv: Sequence[str] = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    return int(arguments.handler(arguments))


if __name__ == "__main__":
    raise SystemExit(main())
