"""Cross-entry consistency checks for the reusable failure registry."""

import re
from pathlib import Path

import pytest

from ._known_failures import (
    active_entries,
    find_cycle,
    find_test_function,
    load_registry,
    parse_canonical_test,
    referenced_ids,
    relationship_graph,
    strict_xfail_ids,
)


pytestmark = pytest.mark.component

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
REGISTRY_PATH = REPOSITORY_ROOT / "tests" / "known_failures.yml"
TEST_ROOT = REPOSITORY_ROOT / "tests"


def test_registry_entries_match_declared_schema_values() -> None:
    registry = load_registry(REGISTRY_PATH)
    entries = active_entries(registry)
    schema = registry["schema"]
    identifier_pattern = re.compile(schema["id_pattern"])
    statuses = set(schema["status_values"])
    classifications = set(schema["classification_values"])

    assert registry["schema_version"] == 1
    assert statuses
    assert classifications
    for entry in entries:
        assert identifier_pattern.fullmatch(entry["id"])
        assert entry["status"] in statuses
        assert entry["classification"] in classifications


def test_registry_entries_are_ordered_unique_and_structurally_complete() -> None:
    registry = load_registry(REGISTRY_PATH)
    entries = active_entries(registry)
    required = set(registry["schema"]["entry_required"])
    ids = [entry["id"] for entry in entries]

    assert ids == sorted(ids)
    assert len(ids) == len(set(ids))

    for entry in entries:
        assert required <= set(entry)
        assert isinstance(entry["canonical_test"], str)
        assert isinstance(entry["affected_profiles"], dict)
        assert isinstance(entry["evidence"], dict)
        assert isinstance(entry["blocked_by"], list)
        assert isinstance(entry["blocks"], list)
        assert len(entry["blocked_by"]) == len(set(entry["blocked_by"]))
        assert len(entry["blocks"]) == len(set(entry["blocks"]))
        assert entry["id"] not in entry["blocked_by"]
        assert entry["id"] not in entry["blocks"]


def test_registry_blocker_links_exist_are_reciprocal_and_acyclic() -> None:
    entries = active_entries(load_registry(REGISTRY_PATH))
    by_id = {entry["id"]: entry for entry in entries}

    for entry in entries:
        for blocker_id in entry["blocked_by"]:
            assert blocker_id in by_id
            assert entry["id"] in by_id[blocker_id]["blocks"]
        for blocked_id in entry["blocks"]:
            assert blocked_id in by_id
            assert entry["id"] in by_id[blocked_id]["blocked_by"]

    cycle = find_cycle(relationship_graph(entries))
    assert cycle is None, "known-failure blocker cycle: {}".format(cycle)


def test_each_canonical_node_exists_and_declares_its_strict_xfail() -> None:
    entries = active_entries(load_registry(REGISTRY_PATH))
    canonical_nodes = [entry["canonical_test"] for entry in entries]

    assert len(canonical_nodes) == len(set(canonical_nodes))
    for entry in entries:
        canonical = parse_canonical_test(
            REPOSITORY_ROOT, entry["canonical_test"]
        )
        assert canonical.path.is_file()
        _, function = find_test_function(canonical)
        assert entry["id"] in strict_xfail_ids(function)


def test_every_registered_failure_is_referenced_by_the_test_suite() -> None:
    entries = active_entries(load_registry(REGISTRY_PATH))
    references = referenced_ids(TEST_ROOT)

    unreferenced = {
        entry["id"] for entry in entries if entry["id"] not in references
    }
    assert not unreferenced
