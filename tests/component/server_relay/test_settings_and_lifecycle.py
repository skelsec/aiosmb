"""Settings, host delegation, and connection ownership boundaries."""

import asyncio
import ast
import importlib
import sys
from pathlib import Path
from typing import Any, List

import pytest

from aiosmb.protocol.common import NegotiateDialects
from tests.component.server_relay.support import (
    FakeGSSAPI,
    FakeTransport,
    StopProbe,
    settle_cancelled,
    wait_for,
)


pytestmark = [pytest.mark.component, pytest.mark.asyncio]

SERVER_CASES = (
    ("aiosmb.server.server", "SMBServer"),
    ("aiosmb.relay.server", "SMBRelayServer"),
)


def import_boundary_module(module_name: str) -> Any:
    try:
        return importlib.import_module(module_name)
    except TypeError:
        if sys.version_info < (3, 9) and module_name.startswith(
            "aiosmb.server"
        ):
            pytest.xfail(
                "blocked by KF-0632: server annotations require Python 3.9"
            )
        raise


@pytest.mark.xfail(
    strict=True,
    reason="KF-0632: server annotations evaluate Python 3.9-only generics",
)
async def test_server_connection_annotations_support_python38() -> None:
    source_path = (
        Path(__file__).parents[3]
        / "aiosmb"
        / "server"
        / "serverconnection.py"
    )
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    unsupported = [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Subscript)
        and isinstance(node.value, ast.Name)
        and node.value.id in {"dict", "list", "set", "tuple", "type"}
    ]

    assert unsupported == []


@pytest.mark.parametrize("module_name,server_name", SERVER_CASES)
async def test_settings_defaults_and_gssapi_factory_are_connection_scoped(
    module_name: str, server_name: str
) -> None:
    module = import_boundary_module(module_name)
    created: List[FakeGSSAPI] = []

    def factory() -> FakeGSSAPI:
        gssapi = FakeGSSAPI()
        created.append(gssapi)
        return gssapi

    first = module.SMBServerSettings(factory, log_callback=None)
    second = module.SMBServerSettings(factory, log_callback=None)
    transport = FakeTransport()

    gssapi = first.create_new_gssapi(transport)

    assert gssapi is created[0]
    assert gssapi.connection is transport
    assert first.preferred_dialects == [NegotiateDialects.SMB202]
    assert (first.MaxTransactSize, first.MaxReadSize, first.MaxWriteSize) == (
        0x100000,
        0x100000,
        0x100000,
    )
    assert first.RequireSigning is False
    assert first.shares == {}
    first.shares["data"] = "/tmp/data"
    assert second.shares == {}
    assert first.ServerGuid is not second.ServerGuid


@pytest.mark.parametrize("module_name,server_name", SERVER_CASES)
async def test_host_run_delegates_without_binding_a_real_socket(
    module_name: str,
    server_name: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = import_boundary_module(module_name)
    observed: List[Any] = []
    sentinel = object()

    class FakeUniServer:
        def __init__(self, target: Any, packetizer: Any) -> None:
            observed.append((target, packetizer))

        async def serve_callback(self, callback: Any) -> Any:
            observed.append(callback)
            return sentinel

    monkeypatch.setattr(module, "UniServer", FakeUniServer)
    settings = module.SMBServerSettings(FakeGSSAPI, log_callback=None)
    target = object()
    server = getattr(module, server_name)(target, settings)

    result = await wait_for(server.run())

    assert result is sentinel
    assert observed[0][0] is target
    assert observed[0][1].__class__.__name__ == "NetBIOSPacketizer"
    assert callable(observed[1])


@pytest.mark.parametrize("module_name,server_name", SERVER_CASES)
async def test_host_tracks_and_stops_a_completed_connection(
    module_name: str,
    server_name: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = import_boundary_module(module_name)
    connection_class_name = (
        "SMBServerConnection"
        if server_name == "SMBServer"
        else "SMBRelayServerConnection"
    )
    instances = []
    logs = []

    class FakeHostedConnection(StopProbe):
        def __init__(
            self,
            settings: Any,
            connection: Any,
            connection_id: int,
        ) -> None:
            super().__init__()
            self.connection = connection
            self.connection_id = connection_id
            instances.append(self)

        async def run(self) -> "asyncio.Task[None]":
            async def completed() -> None:
                return None

            return asyncio.create_task(completed())

    async def log(message: str) -> None:
        logs.append(message)

    monkeypatch.setattr(module, connection_class_name, FakeHostedConnection)
    settings = module.SMBServerSettings(FakeGSSAPI, log_callback=log)
    server = getattr(module, server_name)(object(), settings)
    handler = getattr(server, "_{}__handle_connection".format(server_name))
    transport = FakeTransport()

    await wait_for(handler(transport))

    assert server.connection_ctr == 1
    assert server.connections[settings.ServerGuid] == instances
    assert instances[0].connection is transport
    assert instances[0].stop_calls == 1
    assert any("Got new connection" in entry for entry in logs)
    assert any("Connection end" in entry for entry in logs)


@pytest.mark.xfail(
    strict=True,
    reason="KF-0624: completing one client stops unrelated hosted connections",
)
async def test_host_cleanup_does_not_stop_an_unrelated_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = import_boundary_module("aiosmb.server.server")
    prior = StopProbe()
    instances = []

    class FakeHostedConnection(StopProbe):
        def __init__(
            self,
            settings: Any,
            connection: Any,
            connection_id: int,
        ) -> None:
            super().__init__()
            instances.append(self)

        async def run(self) -> "asyncio.Task[None]":
            async def completed() -> None:
                return None

            return asyncio.create_task(completed())

    monkeypatch.setattr(module, "SMBServerConnection", FakeHostedConnection)
    settings = module.SMBServerSettings(FakeGSSAPI, log_callback=None)
    server = module.SMBServer(object(), settings)
    server.connections[settings.ServerGuid] = [prior]

    await wait_for(server._SMBServer__handle_connection(FakeTransport()))

    assert prior.stop_calls == 0
    assert instances[0].stop_calls == 1


@pytest.mark.xfail(
    strict=True,
    reason="KF-0625: constructor failure triggers a cleanup KeyError",
)
async def test_host_constructor_failure_is_reported_without_cleanup_crash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = import_boundary_module("aiosmb.server.server")
    logs = []

    class BrokenConnection:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            raise RuntimeError("constructor failed")

    async def log(message: str) -> None:
        logs.append(message)

    monkeypatch.setattr(module, "SMBServerConnection", BrokenConnection)
    settings = module.SMBServerSettings(FakeGSSAPI, log_callback=log)
    server = module.SMBServer(object(), settings)

    await wait_for(server._SMBServer__handle_connection(FakeTransport()))

    assert any("constructor failed" in entry for entry in logs)


@pytest.mark.parametrize(
    "module_name,connection_name",
    (
        ("aiosmb.server.serverconnection", "SMBServerConnection"),
        ("aiosmb.relay.serverconnection", "SMBRelayServerConnection"),
    ),
)
async def test_connection_stop_cancels_reader_and_closes_transport(
    module_name: str, connection_name: str
) -> None:
    module = import_boundary_module(module_name)
    release = asyncio.Event()

    class BlockingTransport(FakeTransport):
        async def read(self) -> Any:
            await release.wait()
            if False:
                yield None

    transport = BlockingTransport()
    server_module_name = module_name.rsplit(".", 1)[0] + ".server"
    server_module = import_boundary_module(server_module_name)
    settings = server_module.SMBServerSettings(FakeGSSAPI, log_callback=None)
    connection = getattr(module, connection_name)(settings, transport, 7)
    task = await connection.run()

    await wait_for(connection.stop())
    await settle_cancelled(task)

    assert task.done()
    assert transport.closed is True
    assert transport.close_calls >= 1
