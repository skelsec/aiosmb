"""Fake-backed lifecycle and delegation tests for file-like interfaces."""

import asyncio
import sys
from types import SimpleNamespace
from typing import Any, List, Optional, Tuple

import pytest

if sys.version_info < (3, 9):
    pytest.skip("blocked by KF-0107", allow_module_level=True)

from aiosmb.commons.interfaces.directory import SMBDirectory
from aiosmb.commons.interfaces.file import SMBFile
from aiosmb.commons.interfaces.share import SMBShare
from aiosmb.wintypes.fscc.FileAttributes import FileAttributes


pytestmark = [pytest.mark.component, pytest.mark.asyncio]
TIMEOUT = 0.5


class FakeConnection:
    def __init__(self, payload=b"abcdef"):
        self.MaxReadSize = 2
        self.MaxWriteSize = 3
        self.target = SimpleNamespace(
            get_hostname_or_ip=lambda: "server.invalid"
        )
        self.payload = payload
        self.read_error = None  # type: Optional[Exception]
        self.tree_connect_error = None  # type: Optional[Exception]
        self.tree_connect_calls = []  # type: List[str]
        self.create_calls = []  # type: List[Tuple[Any, ...]]
        self.read_calls = []  # type: List[Tuple[Any, ...]]
        self.write_calls = []  # type: List[Tuple[Any, ...]]
        self.flush_calls = []  # type: List[Tuple[Any, ...]]
        self.close_calls = []  # type: List[Tuple[Any, ...]]
        self.tree_disconnect_calls = []  # type: List[Any]
        self.query_directory_results = []  # type: List[Any]
        self.ioctl_result = object()

    async def tree_connect(self, path):
        self.tree_connect_calls.append(path)
        if self.tree_connect_error is not None:
            return None, self.tree_connect_error
        return SimpleNamespace(tree_id=41, maximal_access=0x1234), None

    async def create(self, *args, **kwargs):
        self.create_calls.append(args + (kwargs,))
        if kwargs.get("return_reply") is True:
            return b"file-id", SimpleNamespace(EndofFile=len(self.payload)), None
        return b"file-id", None

    async def read(self, tree_id, file_id, offset=0, length=0):
        self.read_calls.append((tree_id, file_id, offset, length))
        if self.read_error is not None:
            return None, 0, self.read_error
        return self.payload[offset : offset + length], 0, None

    async def write(self, tree_id, file_id, data, offset=0):
        self.write_calls.append((tree_id, file_id, bytes(data), offset))
        return len(data), None

    async def flush(self, tree_id, file_id):
        self.flush_calls.append((tree_id, file_id))
        return True, None

    async def close(self, tree_id, file_id):
        self.close_calls.append((tree_id, file_id))
        return True, None

    async def tree_disconnect(self, tree_id):
        self.tree_disconnect_calls.append(tree_id)
        return True, None

    async def query_directory(self, tree_id, file_id):
        if not self.query_directory_results:
            return [], None
        result = self.query_directory_results.pop(0)
        if isinstance(result, Exception):
            return None, result
        return result, None

    async def ioctl(self, *args, **kwargs):
        return self.ioctl_result, None


class DirectoryInfo:
    def __init__(self, name, is_directory):
        self.FileName = name
        self.FileAttributes = (
            FileAttributes.FILE_ATTRIBUTE_DIRECTORY
            if is_directory
            else FileAttributes.FILE_ATTRIBUTE_NORMAL
        )
        self.CreationTime = 1
        self.LastAccessTime = 2
        self.LastWriteTime = 3
        self.ChangeTime = 4
        self.AllocationSize = 5
        self.EndOfFile = 6


async def _collect(iterator):
    async def collect_all():
        return [item async for item in iterator]

    return await asyncio.wait_for(collect_all(), timeout=TIMEOUT)


async def test_file_open_read_write_and_close_delegate_to_connection():
    connection = FakeConnection(payload=b"abcdef")
    smb_file = SMBFile.from_uncpath(
        r"\\server.invalid\data\folder\report.bin"
    )

    opened, error = await asyncio.wait_for(
        smb_file.open(connection, mode="r"), timeout=TIMEOUT
    )
    data, error = await asyncio.wait_for(smb_file.read(3), timeout=TIMEOUT)
    await asyncio.wait_for(smb_file.close(), timeout=TIMEOUT)

    assert opened is True
    assert error is None
    assert data == b"abc"
    assert smb_file.size == 6
    assert smb_file.tell() == 3
    assert connection.tree_connect_calls == [r"\\server.invalid\data"]
    assert connection.read_calls == [
        (41, b"file-id", 0, connection.MaxReadSize),
        (41, b"file-id", 2, connection.MaxReadSize),
    ]
    assert connection.close_calls == [(41, b"file-id")]

    writable = SMBFile.from_uncpath(
        r"\\server.invalid\data\folder\output.bin"
    )
    opened, error = await asyncio.wait_for(
        writable.open(connection, mode="w"), timeout=TIMEOUT
    )
    count, error = await asyncio.wait_for(
        writable.write(b"hello"), timeout=TIMEOUT
    )
    await asyncio.wait_for(writable.close(), timeout=TIMEOUT)

    assert opened is True
    assert error is None
    assert count == 5
    assert writable.tell() == 5
    assert [call[2:] for call in connection.write_calls] == [
        (b"hel", 0),
        (b"lo", 3),
    ]
    assert connection.flush_calls == [(41, b"file-id")]


async def test_file_async_context_closes_an_open_handle_on_body_error():
    connection = FakeConnection()
    smb_file = SMBFile.from_uncpath(r"\\server.invalid\data\report.bin")
    opened, error = await asyncio.wait_for(
        smb_file.open(connection, mode="r"), timeout=TIMEOUT
    )
    assert opened is True
    assert error is None

    with pytest.raises(RuntimeError, match="body failed"):
        async with smb_file:
            raise RuntimeError("body failed")

    assert connection.close_calls == [(41, b"file-id")]


@pytest.mark.xfail(
    strict=True,
    reason="KF-0600: SMBFile.close leaves the handle live and closes it twice",
)
async def test_file_close_is_idempotent_and_clears_the_handle():
    connection = FakeConnection()
    smb_file = SMBFile.from_uncpath(r"\\server.invalid\data\report.bin")
    opened, error = await asyncio.wait_for(
        smb_file.open(connection, mode="r"), timeout=TIMEOUT
    )
    assert opened is True
    assert error is None

    await asyncio.wait_for(smb_file.close(), timeout=TIMEOUT)
    await asyncio.wait_for(smb_file.close(), timeout=TIMEOUT)

    assert smb_file.file_id is None
    assert connection.close_calls == [(41, b"file-id")]


@pytest.mark.xfail(
    strict=True,
    reason=(
        "KF-0601: invalid SMBFile modes retain the tree connected before "
        "validation"
    ),
)
async def test_invalid_file_mode_releases_tree_acquired_during_open():
    connection = FakeConnection()
    smb_file = SMBFile.from_uncpath(r"\\server.invalid\data\report.bin")

    opened, error = await asyncio.wait_for(
        smb_file.open(connection, mode="invalid"), timeout=TIMEOUT
    )

    assert opened is False
    assert isinstance(error, Exception)
    assert smb_file.tree_id is None
    assert connection.tree_disconnect_calls == [41]


@pytest.mark.xfail(
    strict=True,
    reason=(
        "KF-0602: read_chunked raises RuntimeError instead of terminating "
        "after its EOF sentinel"
    ),
)
async def test_file_chunk_iterator_terminates_cleanly_after_eof():
    connection = FakeConnection(payload=b"abcd")
    smb_file = SMBFile.from_uncpath(r"\\server.invalid\data\report.bin")
    opened, error = await asyncio.wait_for(
        smb_file.open(connection, mode="r"), timeout=TIMEOUT
    )
    assert opened is True
    assert error is None

    try:
        chunks = await _collect(smb_file.read_chunked(chunksize=2))
    finally:
        await asyncio.wait_for(smb_file.close(), timeout=TIMEOUT)

    assert chunks == [(b"ab", None), (b"cd", None), (None, None)]


@pytest.mark.xfail(
    strict=True,
    reason=(
        "KF-0603: read_chunked repeats a connection error forever instead "
        "of ending the iterator"
    ),
)
async def test_file_chunk_iterator_yields_a_read_error_once_then_stops():
    connection = FakeConnection(payload=b"abcd")
    expected_error = RuntimeError("read failed")
    connection.read_error = expected_error
    smb_file = SMBFile.from_uncpath(r"\\server.invalid\data\report.bin")
    opened, error = await asyncio.wait_for(
        smb_file.open(connection, mode="r"), timeout=TIMEOUT
    )
    assert opened is True
    assert error is None
    iterator = smb_file.read_chunked(chunksize=2)

    try:
        first = await asyncio.wait_for(iterator.__anext__(), timeout=TIMEOUT)
        assert first == (None, expected_error)
        with pytest.raises(StopAsyncIteration):
            await asyncio.wait_for(iterator.__anext__(), timeout=TIMEOUT)
    finally:
        await asyncio.wait_for(iterator.aclose(), timeout=TIMEOUT)
        await asyncio.wait_for(smb_file.close(), timeout=TIMEOUT)


async def test_directory_list_generator_builds_entries_and_closes_handle():
    connection = FakeConnection()
    connection.query_directory_results = [
        [
            DirectoryInfo(".", True),
            DirectoryInfo("child", True),
            DirectoryInfo("report.txt", False),
        ],
        [],
    ]
    directory = SMBDirectory.from_uncpath(r"\\server.invalid\data\root")

    entries = await _collect(directory.list_gen(connection))

    assert [(entry.name, entry_type, error) for entry, entry_type, error in entries] == [
        ("child", "dir", None),
        ("report.txt", "file", None),
    ]
    child, _, _ = entries[0]
    smb_file, _, _ = entries[1]
    assert child.parent_dir is directory
    assert child.fullpath == r"root\child"
    assert child.unc_path == r"\\server.invalid\data\root\child"
    assert smb_file.fullpath == r"root\report.txt"
    assert smb_file.unc_path == r"\\server.invalid\data\root\report.txt"
    assert connection.close_calls == [(41, b"file-id")]


async def test_directory_list_generator_yields_query_error_and_cleans_up():
    connection = FakeConnection()
    expected_error = RuntimeError("enumeration failed")
    connection.query_directory_results = [expected_error]
    directory = SMBDirectory.from_uncpath(r"\\server.invalid\data\root")

    entries = await _collect(directory.list_gen(connection))

    assert entries == [(directory, "dir", expected_error)]
    assert connection.close_calls == [(41, b"file-id")]


async def test_share_connect_populates_tree_metadata_and_root_directory():
    connection = FakeConnection()
    share = SMBShare(
        name="data", fullpath=r"\\server.invalid\data"
    )

    connected, error = await asyncio.wait_for(
        share.connect(connection), timeout=TIMEOUT
    )

    assert connected is True
    assert error is None
    assert share.tree_id == 41
    assert share.maximal_access == 0x1234
    assert list(share.subdirs) == [""]
    root = share.subdirs[""]
    assert root.tree_id == share.tree_id
    assert root.fullpath == ""
    assert root.unc_path == share.unc_path


@pytest.mark.xfail(
    strict=True,
    reason=(
        "KF-0604: connected SMBShare.snapshots reads an uninitialized "
        "local tree identifier"
    ),
)
async def test_connected_share_snapshots_reuses_existing_tree():
    connection = FakeConnection()
    share = SMBShare(
        name="data", fullpath=r"\\server.invalid\data"
    )
    share.tree_id = 41

    snapshots, error = await asyncio.wait_for(
        share.snapshots(connection), timeout=TIMEOUT
    )

    assert snapshots is connection.ioctl_result
    assert error is None
    assert connection.create_calls[0][0] == 41


@pytest.mark.xfail(
    strict=True,
    reason=(
        "KF-0605: SMBShare.snapshots leaks the temporary directory handle"
    ),
)
async def test_share_snapshots_closes_temporary_directory_handle():
    connection = FakeConnection()
    share = SMBShare(
        name="data", fullpath=r"\\server.invalid\data"
    )

    snapshots, error = await asyncio.wait_for(
        share.snapshots(connection), timeout=TIMEOUT
    )

    assert snapshots is connection.ioctl_result
    assert error is None
    assert connection.close_calls == [(41, b"file-id")]


@pytest.mark.xfail(
    strict=True,
    reason=(
        "KF-0606: SMBDirectory.snapshots cleanup masks tree-connect errors "
        "with an unbound file handle"
    ),
)
async def test_directory_snapshot_connect_error_is_returned_unchanged():
    connection = FakeConnection()
    expected_error = RuntimeError("tree connect failed")
    connection.tree_connect_error = expected_error
    directory = SMBDirectory.from_uncpath(r"\\server.invalid\data\root")

    snapshots, error = await asyncio.wait_for(
        directory.snapshots(connection), timeout=TIMEOUT
    )

    assert snapshots is None
    assert error is expected_error
