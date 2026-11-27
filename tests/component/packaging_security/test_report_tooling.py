"""Process-boundary checks for sanitized report artifacts."""

import json
import subprocess
import sys
from pathlib import Path

import pytest


pytestmark = pytest.mark.component

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
REPORT_TOOL = REPOSITORY_ROOT / "tests" / "support" / "reporting.py"


def test_report_cli_writes_only_sanitized_aggregate_data(
    tmp_path: Path,
) -> None:
    secret = "synthetic-cli-secret"
    junit_path = tmp_path / "sensitive-target-name.xml"
    junit_path.write_text(
        """<testsuite><testcase classname="{0}" name="{0}">
<skipped type="pytest.xfail" message="KF-0905: {0}">{0}</skipped>
</testcase></testsuite>""".format(secret),
        encoding="utf-8",
    )
    json_path = tmp_path / "report.json"
    markdown_path = tmp_path / "report.md"

    completed = subprocess.run(
        [
            sys.executable,
            str(REPORT_TOOL),
            "--junit",
            str(junit_path),
            "--json-output",
            str(json_path),
            "--markdown-output",
            str(markdown_path),
        ],
        cwd=str(REPOSITORY_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        check=False,
    )

    assert completed.returncode == 0
    outputs = (
        completed.stdout
        + completed.stderr
        + json_path.read_text(encoding="utf-8")
        + markdown_path.read_text(encoding="utf-8")
    )
    assert secret not in outputs
    assert str(junit_path) not in outputs
    assert "KF-0905" in outputs
    assert json.loads(json_path.read_text(encoding="utf-8"))["counts"] == {
        "failed": 0,
        "passed": 0,
        "skipped": 0,
        "total": 1,
        "xfailed": 1,
    }


def test_report_cli_rejects_malformed_xml_without_echoing_it(
    tmp_path: Path,
) -> None:
    secret = "synthetic-malformed-secret"
    junit_path = tmp_path / "private.xml"
    junit_path.write_text("<testsuite>{}".format(secret), encoding="utf-8")

    completed = subprocess.run(
        [
            sys.executable,
            str(REPORT_TOOL),
            "--junit",
            str(junit_path),
            "--json-output",
            str(tmp_path / "report.json"),
            "--markdown-output",
            str(tmp_path / "report.md"),
        ],
        cwd=str(REPOSITORY_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        check=False,
    )

    assert completed.returncode == 2
    assert secret not in completed.stdout
    assert secret not in completed.stderr
    assert str(junit_path) not in completed.stderr
