"""Offline contracts for scanner target generator implementations."""

import asyncio
import uuid

import pytest

from aiosmb.commons.scanner.targetgen.filetarget import (
    FileTargetGen as QueueFileTargetGen,
)
from aiosmb.commons.scanner.targetgen.listtarget import (
    ListTargetGen as QueueListTargetGen,
)
from aiosmb.examples.scancommons.targetgens import FileTargetGen, ListTargetGen


pytestmark = pytest.mark.component


async def collect(generator):
    return [item async for item in generator.generate()]


def assert_uuid(value: str) -> None:
    assert str(uuid.UUID(value)) == value


@pytest.mark.asyncio
async def test_list_generator_expands_addresses_networks_and_names() -> None:
    rows = await collect(
        ListTargetGen([" 192.0.2.1 ", "192.0.2.4/30", " files.example "])
    )

    assert [target for _, target, error in rows if error is None] == [
        "192.0.2.1",
        "192.0.2.4",
        "192.0.2.5",
        "192.0.2.6",
        "192.0.2.7",
        "files.example",
    ]
    assert all(error is None for _, _, error in rows)
    assert len({target_id for target_id, _, _ in rows}) == len(rows)
    for target_id, _, _ in rows:
        assert_uuid(target_id)


@pytest.mark.asyncio
async def test_file_generator_skips_blanks_and_expands_networks(tmp_path) -> None:
    targets = tmp_path / "targets.txt"
    targets.write_text(
        "\n192.0.2.9\n\n198.51.100.0/31\nhost.example\n",
        encoding="utf-8",
    )

    rows = await collect(FileTargetGen(str(targets)))

    assert [target for _, target, _ in rows] == [
        "192.0.2.9",
        "198.51.100.0",
        "198.51.100.1",
        "host.example",
    ]
    assert all(error is None for _, _, error in rows)


@pytest.mark.asyncio
async def test_file_generator_reports_open_errors_as_data(tmp_path) -> None:
    missing = tmp_path / "missing.txt"

    rows = await collect(FileTargetGen(str(missing)))

    assert len(rows) == 1
    target_id, target, error = rows[0]
    assert target_id is None
    assert target is None
    assert isinstance(error, FileNotFoundError)


@pytest.mark.asyncio
async def test_queue_list_generator_preserves_or_creates_identifiers() -> None:
    generated_queue = asyncio.Queue()
    count, error = await QueueListTargetGen(["one", "two"]).run(generated_queue)

    assert (count, error) == (2, None)
    generated = [generated_queue.get_nowait(), generated_queue.get_nowait()]
    assert [target for _, target in generated] == ["one", "two"]
    for target_id, _ in generated:
        assert_uuid(target_id)

    supplied_queue = asyncio.Queue()
    count, error = await QueueListTargetGen(
        [("id-1", "one"), ("id-2", "two")], with_id=True
    ).run(supplied_queue)

    assert (count, error) == (2, None)
    assert supplied_queue.get_nowait() == ("id-1", "one")
    assert supplied_queue.get_nowait() == ("id-2", "two")


@pytest.mark.asyncio
@pytest.mark.xfail(
    strict=True,
    reason="KF-0643: queue file target generator never increments its count",
)
async def test_queue_file_generator_count_matches_enqueued_targets(tmp_path) -> None:
    targets = tmp_path / "targets.txt"
    targets.write_text("one\ntwo\n", encoding="utf-8")
    queue = asyncio.Queue()

    count, error = await QueueFileTargetGen(str(targets)).run(queue)

    assert error is None
    assert count == queue.qsize() == 2
