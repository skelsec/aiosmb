"""End-to-end scanner orchestration with local fakes."""

import asyncio
import sys
from types import SimpleNamespace

import pytest

if sys.version_info < (3, 9):
    pytest.skip("blocked by KF-0107", allow_module_level=True)

from aiosmb.examples import smbshareenum
from aiosmb.examples.scancommons.internal import EnumProgress
from aiosmb.examples.smbshareenum import SMBFileEnum


pytestmark = pytest.mark.component


class FakeConnection:
    def __init__(self, target):
        self.target = target
        self.entered = False
        self.exited = False

    async def __aenter__(self):
        self.entered = True
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        self.exited = True

    async def login(self):
        return True, None


class FakeFactory:
    def __init__(self):
        self.connections = []

    def create_connection_newtarget(self, target):
        connection = FakeConnection(target)
        self.connections.append(connection)
        return connection


class FakeMachine:
    def __init__(self, connection):
        self.connection = connection

    async def enum_all_recursively(self, **kwargs):
        yield (
            SimpleNamespace(
                unc_path=r"\\files.example\public\report.txt",
                creation_time=None,
                size=12,
                security_descriptor=None,
            ),
            "file",
            None,
        )


class OneTargetGenerator:
    async def generate(self):
        yield "target-id", "files.example", None


@pytest.mark.asyncio
async def test_share_enumerator_runs_generator_worker_and_result_pipeline(
    monkeypatch,
) -> None:
    monkeypatch.setattr(smbshareenum, "SMBMachine", FakeMachine)
    factory = FakeFactory()
    external_results = asyncio.Queue()
    enumerator = SMBFileEnum(
        factory,
        worker_count=2,
        show_pbar=False,
        ext_result_q=external_results,
    )
    enumerator.target_gens.append(OneTargetGenerator())

    success, error = await enumerator.run()

    assert (success, error) == (True, None)
    assert len(factory.connections) == 1
    assert factory.connections[0].entered is True
    assert factory.connections[0].exited is True

    rows = []
    while not external_results.empty():
        rows.append(external_results.get_nowait())

    assert [row.otype for row in rows] == ["file", "progress", "finished"]
    assert rows[0].target == "files.example"
    assert rows[0].target_id == "target-id"
    assert rows[0].to_dict()["size"] == 12
    assert isinstance(rows[1].obj, EnumProgress)
    assert rows[1].obj.total_targets == 1
    assert rows[1].obj.total_finished == 1


@pytest.mark.asyncio
@pytest.mark.xfail(
    strict=True,
    reason="KF-0644: injected result queues do not start result processing",
)
async def test_share_enumerator_starts_processor_for_injected_result_queue() -> None:
    enumerator = SMBFileEnum(
        FakeFactory(),
        worker_count=1,
        show_pbar=False,
        res_q=asyncio.Queue(),
    )

    try:
        success, error = await enumerator.setup()
        assert (success, error) == (True, None)
        assert enumerator.result_processing_task is not None
    finally:
        await enumerator.terminate()
        await asyncio.gather(*enumerator.workers, return_exceptions=True)
