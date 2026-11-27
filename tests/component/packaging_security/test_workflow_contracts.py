"""Trust-boundary contracts for tiered GitHub Actions."""

from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping

import pytest
import yaml


pytestmark = pytest.mark.component

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
WORKFLOW_DIRECTORY = REPOSITORY_ROOT / ".github" / "workflows"
OFFLINE_PATH = WORKFLOW_DIRECTORY / "test-suite.yml"
SAMBA_PATH = WORKFLOW_DIRECTORY / "samba-lab.yml"
GOAD_PATH = WORKFLOW_DIRECTORY / "goad-readonly.yml"


def _load(path: Path) -> Mapping[str, Any]:
    document = yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    assert isinstance(document, dict)
    return document


def _steps(workflow: Mapping[str, Any]) -> Iterable[Mapping[str, Any]]:
    for job in workflow["jobs"].values():
        yield from job["steps"]


def _commands(workflow: Mapping[str, Any]) -> str:
    return "\n".join(
        str(step["run"]) for step in _steps(workflow) if "run" in step
    )


def _artifact_names(workflow: Mapping[str, Any]) -> List[str]:
    return [
        str(step["with"]["name"])
        for step in _steps(workflow)
        if step.get("uses") == "actions/upload-artifact@v4"
    ]


def test_offline_workflow_has_no_live_infrastructure_paths() -> None:
    workflow = _load(OFFLINE_PATH)
    triggers = workflow["on"]
    commands = _commands(workflow)
    matrix = workflow["jobs"]["offline"]["strategy"]["matrix"]["include"]

    assert set(triggers) == {"pull_request", "push"}
    assert {entry["python"] for entry in matrix} == {"3.8", "3.12"}
    assert "tests/unit tests/fake_peer tests/component" in commands
    assert "tests/interop" not in commands
    assert "--run-samba" not in commands
    assert "--run-windows" not in commands
    assert "--run-destructive" not in commands
    assert "--cov-branch" in commands
    assert "--junitxml=" in commands


def test_samba_workflow_is_scheduled_manual_and_uses_managed_runner() -> None:
    workflow = _load(SAMBA_PATH)
    commands = _commands(workflow)

    assert set(workflow["on"]) == {"schedule", "workflow_dispatch"}
    assert workflow["jobs"]["samba"]["runs-on"] == "ubuntu-24.04"
    assert "tests/interop/samba/run-lab.sh" in commands
    assert "--junitxml=" in commands
    assert "--cov-branch" in commands


def test_goad_workflow_is_manual_isolated_and_non_destructive() -> None:
    workflow = _load(GOAD_PATH)
    commands = _commands(workflow)

    assert set(workflow["on"]) == {"workflow_dispatch"}
    assert "--run-destructive" not in commands
    assert "--destructive" not in commands
    assert "test_destructive" not in commands
    assert "--group user" in commands
    assert "--group rpc" in commands
    assert "--group privileged" in commands
    assert "--privileged" in commands
    for job in workflow["jobs"].values():
        labels = set(job["runs-on"])
        assert {"self-hosted", "aiosmb-goad", "isolated"} <= labels
        assert job["environment"] == "aiosmb-goad-readonly"


def test_secret_expressions_stay_out_of_commands_and_artifact_names() -> None:
    workflows = [_load(OFFLINE_PATH), _load(SAMBA_PATH), _load(GOAD_PATH)]

    for workflow in workflows:
        assert "secrets." not in _commands(workflow)
        assert all("secrets." not in name for name in _artifact_names(workflow))
        assert all(step.get("uses") != "actions/cache" for step in _steps(workflow))

    goad = _load(GOAD_PATH)
    secret_bindings: Dict[str, str] = {}
    for step in _steps(goad):
        for name, expression in step.get("env", {}).items():
            if "secrets." in expression:
                secret_bindings[name] = expression

    assert secret_bindings
    assert all(name.startswith("AIOSMB_WINDOWS_") for name in secret_bindings)
    assert all(
        expression.startswith("${{ secrets.")
        and expression.endswith(" }}")
        for expression in secret_bindings.values()
    )
