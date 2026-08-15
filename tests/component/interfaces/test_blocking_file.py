"""Contracts for the synchronous file protocol and its async bridge."""

import asyncio
import sys
from typing import Any, Callable, List, Optional

import pytest

if sys.version_info < (3, 9):
    pytest.skip("blocked by KF-0107", allow_module_level=True)

from aiosmb.commons.interfaces.blocking.file import file as manager_module
from aiosmb.commons.interfaces.blocking.file.blockingfile import (
    SMBBlockingFile,
    Section,
)
from aiosmb.commons.interfaces.blocking.file.file import SMBBlockingFileMgr
from aiosmb.commons.interfaces.blocking.file.protocol import (
    SMBFILECMD,
    SMBFileCloseCommand,
    SMBFileCloseReply,
    SMBFileError,
    SMBFileOpenCommand,
    SMBFileOpenReply,
    SMBFileReadCommand,
    SMBFileReadReply,
    SMBFileTerminateCommand,
    SMBFileWriteCommand,
    SMBFileWriteReply,
)


pytestmark = pytest.mark.component
TIMEOUT = 0.5


class SyncInputQueue:
    def __init__(self):
        self.commands = []  # type: List[Any]

    def put(self, command):
        self.commands.append(command)


class SyncOutputQueue:
    def __init__(self, input_queue, reply_factory):
        self.input_queue = input_queue
        self.reply_factory = reply_factory

    def get(self):
        return self.reply_factory(self.input_queue.commands[-1])


class AsyncQueue:
    def __init__(self):
        self.queue = asyncio.Queue()

    async def coro_get(self):
        return await self.queue.get()

    async def coro_put(self, value):
        await self.queue.put(value)


class FakeRemoteFile:
    instances = []  # type: List["FakeRemoteFile"]

    def __init__(self, path):
        self.path = path
        self.mode = None  # type: Optional[str]
        self.size = 8
        self.position = 0
        self.payload = b"abcdefgh"
        self.close_count = 0
        self.__class__.instances.append(self)

    @classmethod
    def from_remotepath(cls, connection, path):
        return cls(path)

    async def open(self, connection, mode):
        self.mode = mode
        return True, None

    async def seek(self, position, whence=0):
        if whence != 0:
            return None, ValueError("unsupported whence")
        self.position = position
        return True, None

    async def read(self, count):
        data = self.payload[self.position : self.position + count]
        self.position += len(data)
        return data, None

    async def write(self, data):
        self.position += len(data)
        return len(data), None

    async def close(self):
        self.close_count += 1


async def _receive(queue):
    return await asyncio.wait_for(queue.coro_get(), timeout=TIMEOUT)


async def _stop_manager(task, input_queue):
    if not task.done():
        await input_queue.coro_put(None)
    try:
        await asyncio.wait_for(task, timeout=TIMEOUT)
    except asyncio.CancelledError:
        pass
    except asyncio.TimeoutError:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task


@pytest.mark.parametrize(
    "command,command_type,attributes",
    [
        (
            SMBFileOpenCommand(1, r"\data\a.txt", "rb"),
            SMBFILECMD.OPEN,
            {"path": r"\data\a.txt", "mode": "rb"},
        ),
        (
            SMBFileReadCommand(2, 7, 3, 4),
            SMBFILECMD.READ,
            {"handle": 7, "position": 3, "count": 4},
        ),
        (
            SMBFileWriteCommand(3, 7, 5, b"xy"),
            SMBFILECMD.WRITE,
            {"handle": 7, "position": 5, "data": b"xy"},
        ),
        (
            SMBFileCloseCommand(4, 7),
            SMBFILECMD.CLOSE,
            {"handle": 7},
        ),
        (
            SMBFileTerminateCommand(5),
            SMBFILECMD.TERMINATE,
            {},
        ),
    ],
)
def test_blocking_protocol_commands_preserve_correlation_fields(
    command, command_type, attributes
):
    assert command.cmd_id in range(1, 6)
    assert command.cmd_type is command_type
    for name, expected in attributes.items():
        assert getattr(command, name) == expected


def test_section_cache_uses_half_open_slices_for_contained_reads():
    section = Section(10, b"abcdef")

    assert section.inbuffer(10, 6) is True
    assert section.read(11, 3) == b"bcd"
    assert section.inbuffer(9, 1) is False
    assert section.inbuffer(15, 2) is False


def test_blocking_file_open_read_cache_seek_and_close_round_trip():
    input_queue = SyncInputQueue()

    def make_reply(command):
        if command.cmd_type is SMBFILECMD.OPEN:
            return SMBFileOpenReply(command.cmd_id, 12, 10)
        if command.cmd_type is SMBFILECMD.READ:
            return SMBFileReadReply(command.cmd_id, command.handle, b"abcdef")
        if command.cmd_type is SMBFILECMD.CLOSE:
            return SMBFileCloseReply(command.cmd_id, command.handle)
        raise AssertionError("unexpected command")

    output_queue = SyncOutputQueue(input_queue, make_reply)
    blocking_file = SMBBlockingFile(input_queue, output_queue, buffer_size=6)

    blocking_file.open(r"\data\report.bin", "rb")
    first = blocking_file.read(2)
    second = blocking_file.read(2)
    blocking_file.seek(-1, whence=1)
    third = blocking_file.read(2)
    blocking_file.close()

    assert blocking_file.handle == 12
    assert blocking_file.filesize == 10
    assert (first, second, third) == (b"ab", b"cd", b"de")
    assert blocking_file.tell() == 5
    assert [command.cmd_type for command in input_queue.commands] == [
        SMBFILECMD.OPEN,
        SMBFILECMD.READ,
        SMBFILECMD.CLOSE,
    ]
    assert input_queue.commands[1].count == 6


def test_blocking_file_surfaces_bridge_errors():
    input_queue = SyncInputQueue()
    output_queue = SyncOutputQueue(
        input_queue,
        lambda command: SMBFileError(command.cmd_id, "peer failed"),
    )
    blocking_file = SMBBlockingFile(input_queue, output_queue)

    with pytest.raises(Exception, match="peer failed"):
        blocking_file.open(r"\data\report.bin", "rb")


@pytest.mark.xfail(
    strict=True,
    reason=(
        "KF-0607: SMBBlockingFile accepts a same-type reply with a stale "
        "command identifier"
    ),
)
def test_blocking_file_rejects_mismatched_reply_identifier():
    input_queue = SyncInputQueue()
    output_queue = SyncOutputQueue(
        input_queue,
        lambda command: SMBFileOpenReply(command.cmd_id + 1, 9, 1),
    )
    blocking_file = SMBBlockingFile(input_queue, output_queue)
    command = SMBFileOpenCommand(20, r"\data\report.bin", "rb")

    reply = blocking_file.sr(command)

    assert reply.cmd_id == command.cmd_id


@pytest.mark.xfail(
    strict=True,
    reason="KF-0608: SMBBlockingFile.write does not advance its position",
)
def test_blocking_file_write_advances_position_by_reply_count():
    input_queue = SyncInputQueue()
    output_queue = SyncOutputQueue(
        input_queue,
        lambda command: SMBFileWriteReply(
            command.cmd_id, command.handle, len(command.data)
        ),
    )
    blocking_file = SMBBlockingFile(input_queue, output_queue)
    blocking_file.handle = 3

    blocking_file.write(b"payload")

    assert blocking_file.tell() == len(b"payload")


@pytest.mark.xfail(
    strict=True,
    reason=(
        "KF-0609: SMBBlockingFile.terminate constructs but never sends its "
        "termination command"
    ),
)
def test_blocking_file_terminate_sends_protocol_command():
    input_queue = SyncInputQueue()
    output_queue = SyncOutputQueue(input_queue, lambda command: None)
    blocking_file = SMBBlockingFile(input_queue, output_queue)

    blocking_file.terminate()

    assert len(input_queue.commands) == 1
    assert input_queue.commands[0].cmd_type is SMBFILECMD.TERMINATE


@pytest.mark.asyncio
async def test_async_bridge_delegates_open_read_and_close(monkeypatch):
    FakeRemoteFile.instances = []
    monkeypatch.setattr(manager_module, "SMBFile", FakeRemoteFile)
    input_queue = AsyncQueue()
    output_queue = AsyncQueue()
    manager = SMBBlockingFileMgr(object(), input_queue, output_queue)
    task = asyncio.create_task(manager.run())

    try:
        await input_queue.coro_put(
            SMBFileOpenCommand(1, r"\data\report.bin", "rb")
        )
        opened = await _receive(output_queue)
        await input_queue.coro_put(
            SMBFileReadCommand(2, opened.handle, 2, 3)
        )
        read = await _receive(output_queue)
        await input_queue.coro_put(SMBFileCloseCommand(3, opened.handle))
        closed = await _receive(output_queue)

        assert isinstance(opened, SMBFileOpenReply)
        assert opened.filesize == 8
        assert isinstance(read, SMBFileReadReply)
        assert read.data == b"cde"
        assert isinstance(closed, SMBFileCloseReply)
        assert FakeRemoteFile.instances[0].close_count == 1
    finally:
        await _stop_manager(task, input_queue)


@pytest.mark.asyncio
@pytest.mark.xfail(
    strict=True,
    reason=(
        "KF-0610: async blocking bridge removes a handle after WRITE and "
        "cannot close it"
    ),
)
async def test_async_bridge_keeps_written_handle_open_until_close(monkeypatch):
    FakeRemoteFile.instances = []
    monkeypatch.setattr(manager_module, "SMBFile", FakeRemoteFile)
    input_queue = AsyncQueue()
    output_queue = AsyncQueue()
    manager = SMBBlockingFileMgr(object(), input_queue, output_queue)
    task = asyncio.create_task(manager.run())

    try:
        await input_queue.coro_put(
            SMBFileOpenCommand(1, r"\data\report.bin", "wb")
        )
        opened = await _receive(output_queue)
        await input_queue.coro_put(
            SMBFileWriteCommand(2, opened.handle, 0, b"abc")
        )
        written = await _receive(output_queue)
        await input_queue.coro_put(SMBFileCloseCommand(3, opened.handle))
        closed = await _receive(output_queue)

        assert isinstance(written, SMBFileWriteReply)
        assert written.count == 3
        assert isinstance(closed, SMBFileCloseReply)
        assert FakeRemoteFile.instances[0].close_count == 1
    finally:
        await _stop_manager(task, input_queue)


@pytest.mark.asyncio
@pytest.mark.xfail(
    strict=True,
    reason=(
        "KF-0611: bridge termination mutates the handle dictionary during "
        "iteration"
    ),
)
async def test_async_bridge_termination_closes_every_live_handle(monkeypatch):
    FakeRemoteFile.instances = []
    monkeypatch.setattr(manager_module, "SMBFile", FakeRemoteFile)
    input_queue = AsyncQueue()
    output_queue = AsyncQueue()
    manager = SMBBlockingFileMgr(object(), input_queue, output_queue)
    task = asyncio.create_task(manager.run())

    try:
        for command_id in (1, 2):
            await input_queue.coro_put(
                SMBFileOpenCommand(
                    command_id,
                    r"\data\report-%s.bin" % command_id,
                    "rb",
                )
            )
            await _receive(output_queue)

        await input_queue.coro_put(SMBFileTerminateCommand(3))
        await asyncio.wait_for(task, timeout=TIMEOUT)

        assert [item.close_count for item in FakeRemoteFile.instances] == [1, 1]
        assert manager.filehandle == {}
        assert output_queue.queue.empty()
    finally:
        await _stop_manager(task, input_queue)
