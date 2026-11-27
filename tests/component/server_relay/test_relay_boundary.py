"""Relay authentication, queue, and SMB 2.0.2 boundary behavior."""

import asyncio
import sys
from typing import Any, List, Tuple

import pytest

from aiosmb.protocol.common import NegotiateDialects
from aiosmb.protocol.smb2.command_codes import SMB2Command
from aiosmb.protocol.smb2.commands import ECHO_REQ, SESSION_SETUP_REQ, TREE_CONNECT_REQ
from aiosmb.protocol.smb2.headers import SMB2HeaderFlag
from aiosmb.protocol.smb2.message import SMB2Message
from aiosmb.relay.server import SMBServerSettings
from aiosmb.relay.serverconnection import (
    SMBConnectionStatus,
    SMBRelayServerConnection,
)
from aiosmb.wintypes.ntstatus import NTStatus
from tests.component.server_relay.support import (
    FakeGSSAPI,
    FakeTransport,
    make_request,
    settle_cancelled,
    wait_for,
)


pytestmark = [pytest.mark.component, pytest.mark.asyncio]


def make_relay_connection(
    gssapi: FakeGSSAPI = None,
) -> Tuple[SMBRelayServerConnection, FakeTransport, FakeGSSAPI]:
    selected_gssapi = gssapi or FakeGSSAPI()
    transport = FakeTransport()
    settings = SMBServerSettings(
        lambda: selected_gssapi, log_callback=None
    )
    connection = SMBRelayServerConnection(settings, transport, connection_id=13)
    return connection, transport, selected_gssapi


async def test_relay_smb202_negotiate_advertises_relay_capabilities() -> None:
    connection, transport, gssapi = make_relay_connection()

    await wait_for(
        connection.negotiate(
            make_request(ECHO_REQ(), SMB2Command.NEGOTIATE, message_id=5)
        )
    )

    reply = SMB2Message.from_bytes(transport.writes[0])
    assert reply.header.Command == SMB2Command.NEGOTIATE
    assert reply.header.Status == NTStatus.SUCCESS
    assert reply.command.DialectRevision == NegotiateDialects.SMB202
    assert reply.command.Buffer == gssapi.get_mechtypes_list()
    assert connection.selected_dialect == NegotiateDialects.SMB202
    assert connection.SupportsMultiCredit is True
    assert connection.status == SMBConnectionStatus.SESSIONSETUP


async def test_relay_session_setup_runs_bounded_challenge_and_finish() -> None:
    gssapi = FakeGSSAPI(
        relay_steps=(
            (b"relay-challenge", True, None),
            (None, False, None),
        ),
        finished=(b"", None),
        session_key=b"\x42" * 16,
    )
    connection, transport, _ = make_relay_connection(gssapi)
    connection.status = SMBConnectionStatus.SESSIONSETUP
    request = SESSION_SETUP_REQ()
    request.Buffer = b"client-token"
    message = make_request(
        request, SMB2Command.SESSION_SETUP, message_id=7
    )

    first_result = await wait_for(connection.session_setup(message))
    first_reply = SMB2Message.from_bytes(transport.writes[-1])
    assert first_result == (True, None)
    assert first_reply.header.Status == NTStatus.MORE_PROCESSING_REQUIRED
    assert first_reply.command.Buffer == b"relay-challenge"
    assert connection.status == SMBConnectionStatus.SESSIONSETUP

    second_result = await wait_for(connection.session_setup(message))
    final_reply = SMB2Message.from_bytes(transport.writes[-1])
    assert second_result == (False, None)
    assert final_reply.header.Status == NTStatus.SUCCESS
    assert SMB2HeaderFlag.SMB2_FLAGS_SIGNED in final_reply.header.Flags
    assert connection.SessionKey == b"\x42" * 16
    assert connection.status == SMBConnectionStatus.RUNNING
    assert gssapi.relay_calls == [b"client-token", b"client-token"]


async def test_relay_queue_worker_uses_relay_login_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if sys.version_info < (3, 9):
        pytest.skip("blocked by KF-0107")
    import aiosmb.commons.connection.target as target_module
    import aiosmb.commons.interfaces.machine as machine_module
    import aiosmb.connection as connection_module
    import aiosmb.relay.server as relay_server

    observed: List[Any] = []
    listed = asyncio.Event()
    credential = object()

    class FakeTarget:
        def __init__(self, address: str) -> None:
            self.address = address

    class FakeConnection:
        def __init__(
            self,
            item: Any,
            target: Any,
            preserve_gssapi: bool,
            nosign: bool,
        ) -> None:
            observed.append(
                (item, target, preserve_gssapi, nosign)
            )

        async def login(self) -> Tuple[bool, None]:
            return True, None

    class FakeMachine:
        def __init__(self, connection: Any) -> None:
            self.connection = connection

        async def list_shares(self) -> Any:
            listed.set()
            yield "IPC$", None

    monkeypatch.setattr(target_module, "SMBTarget", FakeTarget)
    monkeypatch.setattr(connection_module, "SMBConnection", FakeConnection)
    monkeypatch.setattr(machine_module, "SMBMachine", FakeMachine)
    queue = asyncio.Queue()
    worker = asyncio.create_task(relay_server.test_relay_queue(queue))

    try:
        await wait_for(queue.put(credential))
        await wait_for(listed.wait())
    finally:
        await settle_cancelled(worker)

    assert len(observed) == 1
    item, target, preserve_gssapi, nosign = observed[0]
    assert item is credential
    assert target.address == "10.10.10.2"
    assert preserve_gssapi is False
    assert nosign is True


async def test_relay_factory_can_publish_connection_context_to_queue() -> None:
    queue = asyncio.Queue()

    class QueueGSSAPI(FakeGSSAPI):
        def set_connection_info(self, connection: Any) -> None:
            super().set_connection_info(connection)
            queue.put_nowait(connection)

    transport = FakeTransport()
    settings = SMBServerSettings(QueueGSSAPI, log_callback=None)

    gssapi = settings.create_new_gssapi(transport)
    published = await wait_for(queue.get())

    assert gssapi.connection is transport
    assert published is transport
    assert queue.empty()


async def test_relay_tree_connect_returns_disk_and_pipe_share_types() -> None:
    connection, transport, _ = make_relay_connection()
    connection.status = SMBConnectionStatus.RUNNING

    disk = TREE_CONNECT_REQ()
    disk.Path = r"\\server.invalid\data"
    await wait_for(
        connection.tree_connect(
            make_request(disk, SMB2Command.TREE_CONNECT, message_id=11)
        )
    )
    disk_reply = SMB2Message.from_bytes(transport.writes[-1])

    pipe = TREE_CONNECT_REQ()
    pipe.Path = r"\\server.invalid\IPC$"
    await wait_for(
        connection.tree_connect(
            make_request(pipe, SMB2Command.TREE_CONNECT, message_id=12)
        )
    )
    pipe_reply = SMB2Message.from_bytes(transport.writes[-1])

    assert disk_reply.header.Status == NTStatus.SUCCESS
    assert disk_reply.command.ShareType.name == "DISK"
    assert pipe_reply.header.Status == NTStatus.SUCCESS
    assert pipe_reply.command.ShareType.name == "PIPE"


@pytest.mark.xfail(
    strict=True,
    reason="KF-0628: relay CREATE dispatch calls a missing handler",
)
async def test_relay_create_dispatch_returns_a_protocol_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = make_request(ECHO_REQ(), SMB2Command.CREATE, message_id=67)
    connection, _, _ = make_relay_connection()
    transport = FakeTransport([b"\xfe"])
    connection.connection = transport
    connection.status = SMBConnectionStatus.RUNNING
    monkeypatch.setattr(
        "aiosmb.relay.serverconnection.SMB2Message.from_bytes",
        lambda data: request,
    )
    task = await connection.run()

    await settle_cancelled(task)

    assert len(transport.writes) == 1
    response = SMB2Message.from_bytes(transport.writes[0])
    assert response.header.MessageId == 67


@pytest.mark.xfail(
    strict=True,
    reason="KF-0629: relay IOCTL dispatch exits without a response",
)
async def test_relay_ioctl_dispatch_returns_a_protocol_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = make_request(ECHO_REQ(), SMB2Command.IOCTL, message_id=71)
    connection, _, _ = make_relay_connection()
    transport = FakeTransport([b"\xfe"])
    connection.connection = transport
    connection.status = SMBConnectionStatus.RUNNING
    monkeypatch.setattr(
        "aiosmb.relay.serverconnection.SMB2Message.from_bytes",
        lambda data: request,
    )
    task = await connection.run()

    await settle_cancelled(task)

    assert len(transport.writes) == 1
    response = SMB2Message.from_bytes(transport.writes[0])
    assert response.header.MessageId == 71


@pytest.mark.xfail(
    strict=True,
    reason="KF-0630: relay TREE_CONNECT never assigns a TreeId",
)
async def test_relay_tree_connect_assigns_nonzero_tree_id() -> None:
    connection, transport, _ = make_relay_connection()
    connection.status = SMBConnectionStatus.RUNNING
    request = TREE_CONNECT_REQ()
    request.Path = r"\\server.invalid\data"

    await wait_for(
        connection.tree_connect(
            make_request(request, SMB2Command.TREE_CONNECT, message_id=73)
        )
    )

    reply = SMB2Message.from_bytes(transport.writes[-1])
    assert reply.header.TreeId > 0


@pytest.mark.xfail(
    strict=True,
    reason="KF-0631: relay IPC$ recognition is case-sensitive",
)
async def test_relay_ipc_share_detection_is_case_insensitive() -> None:
    connection, transport, _ = make_relay_connection()
    connection.status = SMBConnectionStatus.RUNNING
    request = TREE_CONNECT_REQ()
    request.Path = r"\\server.invalid\ipc$"

    await wait_for(
        connection.tree_connect(
            make_request(request, SMB2Command.TREE_CONNECT, message_id=79)
        )
    )

    reply = SMB2Message.from_bytes(transport.writes[-1])
    assert reply.command.ShareType.name == "PIPE"
