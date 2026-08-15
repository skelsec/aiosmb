"""Bounded, in-process transport support for SMB connection tests."""

import asyncio
import inspect
from collections import deque
from contextlib import asynccontextmanager
from types import SimpleNamespace
from typing import Any, AsyncIterator, Awaitable, Callable, Deque, Iterable, List, Optional, Union


DEFAULT_TIMEOUT = 1.0
_EOF = object()

ScriptResult = Optional[
    Union[bytes, BaseException, Iterable[Union[bytes, BaseException]]]
]
ScriptAction = Union[
    ScriptResult,
    Callable[[bytes, "ScriptedSMBTransport"], Union[ScriptResult, Awaitable[ScriptResult]]],
]


class ScriptedSMBTransport:
    """Record writes and replay a finite script through ``read``.

    Script actions are consumed one per write. An action can be bytes, an
    exception, an iterable of either, a callback, or an async callback.
    Callbacks receive the recorded write and this transport.
    """

    def __init__(self, script: Iterable[ScriptAction] = ()) -> None:
        self._script: Deque[ScriptAction] = deque(script)
        self._incoming: "asyncio.Queue[Any]" = asyncio.Queue()
        self._write_changed = asyncio.Event()
        self.writes: List[bytes] = []
        self.closed = False
        self.packetizer = SimpleNamespace(buffer_size=None)

    async def read(self) -> AsyncIterator[Optional[bytes]]:
        while True:
            item = await self._incoming.get()
            if item is _EOF:
                return
            if isinstance(item, BaseException):
                raise item
            yield item

    async def write(self, data: bytes) -> None:
        if self.closed:
            raise RuntimeError("scripted transport is closed")

        wire_data = bytes(data)
        self.writes.append(wire_data)
        self._write_changed.set()

        if not self._script:
            return

        action = self._script.popleft()
        result: ScriptResult
        if callable(action):
            pending_result = action(wire_data, self)
            if inspect.isawaitable(pending_result):
                result = await pending_result
            else:
                result = pending_result
        else:
            result = action
        await self._enqueue_result(result)

    async def _enqueue_result(self, result: ScriptResult) -> None:
        if result is None:
            return
        if isinstance(result, (bytes, BaseException)):
            await self._incoming.put(result)
            return
        for item in result:
            if not isinstance(item, (bytes, BaseException)):
                raise TypeError("script results must contain bytes or exceptions")
            await self._incoming.put(item)

    async def feed(self, data: bytes) -> None:
        if self.closed:
            raise RuntimeError("scripted transport is closed")
        await self._incoming.put(bytes(data))

    async def feed_error(self, error: BaseException) -> None:
        if self.closed:
            raise RuntimeError("scripted transport is closed")
        await self._incoming.put(error)

    async def feed_eof(self) -> None:
        if not self.closed:
            await self._incoming.put(None)

    async def wait_for_writes(
        self, count: int, timeout: float = DEFAULT_TIMEOUT
    ) -> List[bytes]:
        async def wait_until_ready() -> None:
            while len(self.writes) < count:
                self._write_changed.clear()
                if len(self.writes) < count:
                    await self._write_changed.wait()

        await asyncio.wait_for(wait_until_ready(), timeout=timeout)
        return list(self.writes)

    async def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        await self._incoming.put(_EOF)

    @property
    def remaining_actions(self) -> int:
        return len(self._script)


def start_connection_reader(connection: Any, transport: ScriptedSMBTransport) -> asyncio.Task:
    """Attach a transport and start SMBConnection's existing receive loop."""

    connection.network_connection = transport
    connection.connection_closed_evt = asyncio.Event()
    task = asyncio.create_task(connection._SMBConnection__handle_smb_in())
    connection.incoming_task = task
    return task


async def stop_connection_reader(
    connection: Any,
    transport: ScriptedSMBTransport,
    timeout: float = DEFAULT_TIMEOUT,
) -> None:
    """Cancel and await the receive loop, then close the transport."""

    task = connection.incoming_task
    if task is not None and not task.done():
        await asyncio.wait_for(connection.disconnect(), timeout=timeout)
    if task is not None:
        try:
            await asyncio.wait_for(task, timeout=timeout)
        except asyncio.CancelledError:
            pass
    await asyncio.wait_for(transport.close(), timeout=timeout)


@asynccontextmanager
async def connection_reader(
    connection: Any,
    transport: ScriptedSMBTransport,
    timeout: float = DEFAULT_TIMEOUT,
) -> AsyncIterator[asyncio.Task]:
    task = start_connection_reader(connection, transport)
    try:
        yield task
    finally:
        await stop_connection_reader(connection, transport, timeout=timeout)
