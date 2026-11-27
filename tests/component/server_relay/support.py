"""Local, bounded test doubles for the in-repository SMB servers."""

import asyncio
from collections import deque
from typing import Any, AsyncIterator, Deque, Iterable, List, Optional, Tuple

from aiosmb.protocol.smb2.headers import SMB2Header_SYNC
from aiosmb.protocol.smb2.message import SMB2Message


TIMEOUT = 0.75


class FakeTransport:
    """Finite SMB transport that records writes and never opens a socket."""

    def __init__(self, incoming: Iterable[Optional[bytes]] = ()) -> None:
        self.incoming = list(incoming)
        self.writes: List[bytes] = []
        self.close_calls = 0
        self.closed = False

    async def read(self) -> AsyncIterator[Optional[bytes]]:
        for item in self.incoming:
            yield item

    async def write(self, data: bytes) -> None:
        if self.closed:
            raise RuntimeError("fake transport is closed")
        self.writes.append(bytes(data))

    async def close(self) -> None:
        self.close_calls += 1
        self.closed = True


class FakeGSSAPI:
    """Authentication facade with deterministic server and relay scripts."""

    def __init__(
        self,
        relay_steps: Iterable[Tuple[Optional[bytes], bool, Optional[Exception]]] = (),
        finished: Tuple[Optional[bytes], Optional[Exception]] = (b"", None),
        session_key: bytes = b"\x11" * 16,
    ) -> None:
        self.connection = None
        self.relay_steps: Deque[
            Tuple[Optional[bytes], bool, Optional[Exception]]
        ] = deque(relay_steps)
        self.finished = finished
        self.session_key = session_key
        self.server_calls: List[bytes] = []
        self.relay_calls: List[bytes] = []

    def set_connection_info(self, connection: Any) -> None:
        self.connection = connection

    def get_mechtypes_list(self) -> bytes:
        return b"test-mechtypes"

    async def authenticate_server(
        self, token: bytes
    ) -> Tuple[bytes, bool, Optional[Exception]]:
        self.server_calls.append(token)
        return b"challenge", True, None

    async def authenticate_server_finished(
        self,
    ) -> Tuple[bytes, Optional[Exception]]:
        return self.finished

    async def authenticate_relay_server(
        self, token: bytes
    ) -> Tuple[Optional[bytes], bool, Optional[Exception]]:
        self.relay_calls.append(token)
        if not self.relay_steps:
            raise AssertionError("relay authentication script exhausted")
        return self.relay_steps.popleft()

    async def authenticate_relay_server_finished(
        self,
    ) -> Tuple[Optional[bytes], Optional[Exception]]:
        return self.finished

    def get_session_key(self) -> bytes:
        return self.session_key


class StopProbe:
    def __init__(self) -> None:
        self.stop_calls = 0

    async def stop(self) -> None:
        self.stop_calls += 1


def make_request(
    command: Any,
    command_code: Any,
    message_id: int = 37,
    tree_id: int = 0,
    session_id: int = 1,
    credit_charge: int = 1,
    credit_request: int = 1,
) -> SMB2Message:
    header = SMB2Header_SYNC()
    header.Command = command_code
    header.CreditCharge = credit_charge
    header.CreditReq = credit_request
    header.Flags = 0
    header.MessageId = message_id
    header.TreeId = tree_id
    header.SessionId = session_id
    return SMB2Message(header, command)


async def wait_for(awaitable: Any) -> Any:
    return await asyncio.wait_for(awaitable, timeout=TIMEOUT)


async def settle_cancelled(task: "asyncio.Task[Any]") -> None:
    if not task.done():
        task.cancel()
    try:
        await asyncio.wait_for(task, timeout=TIMEOUT)
    except asyncio.CancelledError:
        pass
