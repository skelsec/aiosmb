"""Unit coverage for secret-minimal CI report generation."""

import json
from pathlib import Path

import pytest

from tests.support.reporting import (
    ReportError,
    build_report,
    compare_registries,
    load_registry_state,
    render_markdown,
    summarize_junit,
    summarize_junit_files,
)


pytestmark = pytest.mark.unit


def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def test_junit_summary_counts_outcomes_and_known_failure_ids(
    tmp_path: Path,
) -> None:
    junit = _write(
        tmp_path / "junit.xml",
        """<?xml version="1.0" encoding="utf-8"?>
<testsuites>
  <testsuite name="offline">
    <testcase classname="safe" name="pass" />
    <testcase classname="safe" name="skip">
      <skipped type="pytest.skip" message="capability unavailable" />
    </testcase>
    <testcase classname="safe" name="xfail">
      <skipped type="pytest.xfail" message="KF-0901: expected defect" />
    </testcase>
    <testcase classname="safe" name="failure">
      <failure message="[XPASS(strict)] KF-0902">diagnostic</failure>
    </testcase>
    <testcase classname="safe" name="error">
      <error message="collection failed">diagnostic</error>
    </testcase>
  </testsuite>
</testsuites>
""",
    )

    summary = summarize_junit(junit)

    assert summary.counts.as_dict() == {
        "total": 5,
        "passed": 1,
        "skipped": 1,
        "xfailed": 1,
        "failed": 2,
    }
    assert summary.xfailed_ids == ("KF-0901",)
    assert summary.failed_ids == ("KF-0902",)
    assert summary.skipped_ids == ()


def test_junit_summary_accepts_namespaces_and_combines_files(
    tmp_path: Path,
) -> None:
    first = _write(
        tmp_path / "first.xml",
        """<testsuite xmlns="urn:junit"><testcase name="one" /></testsuite>""",
    )
    second = _write(
        tmp_path / "second.xml",
        """<testsuite><testcase name="two"><skipped type="pytest.xfail"
message="KF-0903" /></testcase></testsuite>""",
    )

    summary = summarize_junit_files([first, second])

    assert summary.counts.total == 2
    assert summary.counts.passed == 1
    assert summary.counts.xfailed == 1
    assert summary.xfailed_ids == ("KF-0903",)


def test_invalid_junit_error_does_not_copy_input_or_path(
    tmp_path: Path,
) -> None:
    secret = "synthetic-report-secret"
    path = _write(tmp_path / "private-host.xml", "<testsuite>{}".format(secret))

    with pytest.raises(ReportError) as raised:
        summarize_junit(path)

    message = str(raised.value)
    assert message == "invalid or unreadable JUnit XML"
    assert secret not in message
    assert str(path) not in message


def test_registry_comparison_reports_only_stable_fields(tmp_path: Path) -> None:
    registry = _write(
        tmp_path / "known.yml",
        """
known_failures:
  - id: KF-0900
    status: confirmed
    classification: production_defect
    evidence: synthetic-report-secret
  - id: KF-0901
    status: resolved
    classification: production_defect
""",
    )
    baseline = {
        "KF-0900": ("planned", "planned_feature"),
        "KF-0902": ("confirmed", "production_defect"),
    }

    current = load_registry_state(registry)
    changes = compare_registries(current, baseline)

    assert current == {
        "KF-0900": ("confirmed", "production_defect"),
        "KF-0901": ("resolved", "production_defect"),
    }
    assert changes == {
        "available": True,
        "added": ["KF-0901"],
        "removed": ["KF-0902"],
        "status_changed": [
            {"id": "KF-0900", "from": "planned", "to": "confirmed"}
        ],
        "classification_changed": [
            {
                "id": "KF-0900",
                "from": "planned_feature",
                "to": "production_defect",
            }
        ],
    }
    assert "synthetic-report-secret" not in json.dumps(changes)


def test_registry_state_rejects_unlisted_values_without_echoing_them(
    tmp_path: Path,
) -> None:
    secret = "synthetic-status-secret"
    registry = _write(
        tmp_path / "known.yml",
        """
known_failures:
  - id: KF-0900
    status: {}
    classification: production_defect
""".format(secret),
    )

    with pytest.raises(ReportError) as raised:
        load_registry_state(registry)

    assert str(raised.value) == "invalid known-failure registry entry"
    assert secret not in str(raised.value)


def test_rendered_reports_exclude_junit_diagnostics(tmp_path: Path) -> None:
    secret = "synthetic-report-secret"
    junit = _write(
        tmp_path / "private-host.xml",
        """<testsuite><testcase classname="{}" name="{}">
<failure message="{} KF-0904">{}</failure>
</testcase></testsuite>""".format(secret, secret, secret, secret),
    )

    report = build_report(
        summarize_junit(junit),
        registry={"KF-0904": ("confirmed", "production_defect")},
    )
    serialized = json.dumps(report)
    markdown = render_markdown(report)

    assert secret not in serialized
    assert secret not in markdown
    assert str(junit) not in serialized
    assert report["known_failures"]["failed"] == ["KF-0904"]


def test_unregistered_known_failure_ids_are_visible(tmp_path: Path) -> None:
    junit = _write(
        tmp_path / "junit.xml",
        """<testsuite><testcase name="xfail">
<skipped type="pytest.xfail" message="KF-0999" />
</testcase></testsuite>""",
    )

    report = build_report(summarize_junit(junit), registry={})

    assert report["known_failures"]["unregistered"] == ["KF-0999"]
