"""Focused tests for the SMB server storage boundary."""

import ast
import threading
from pathlib import Path

import pytest

from aiosmb.server.filesystem import (
    FilesystemObjectType,
    InvalidHandleError,
    InvalidPathError,
    LocalFilesystemBackend,
    SMBFileId,
    ShareConfig,
    normalize_relative_path,
    normalize_shares,
)


pytestmark = pytest.mark.unit


def test_legacy_share_mapping_normalizes_to_metadata(tmp_path: Path) -> None:
    class Settings:
        shares = {
            "Data": str(tmp_path),
            "ReadOnly": {
                "path": tmp_path,
                "remark": "published files",
                "read_only": True,
            },
        }

    shares = normalize_shares(Settings())

    assert shares["Data"] == ShareConfig(name="Data", root=tmp_path)
    assert shares["ReadOnly"].metadata.name == "ReadOnly"
    assert shares["ReadOnly"].metadata.remark == "published files"
    assert shares["ReadOnly"].metadata.read_only is True


@pytest.mark.parametrize(
    "unsafe_path",
    (
        "/etc/passwd",
        r"\windows\system32",
        r"\\server\share\file",
        r"C:\Windows\system.ini",
        "C:relative.txt",
        "..",
        "../outside",
        "safe/../../outside",
        "name\x00suffix",
    ),
)
@pytest.mark.asyncio
async def test_path_normalization_rejects_unsafe_names(
    tmp_path: Path, unsafe_path: str
) -> None:
    backend = LocalFilesystemBackend({"data": tmp_path})

    with pytest.raises(InvalidPathError):
        normalize_relative_path(unsafe_path)
    with pytest.raises(InvalidPathError):
        await backend.resolve_path("data", unsafe_path)


@pytest.mark.asyncio
async def test_symlink_escape_is_rejected_but_contained_symlink_is_safe(
    tmp_path: Path,
) -> None:
    share_root = tmp_path / "share"
    outside_root = tmp_path / "outside"
    share_root.mkdir()
    outside_root.mkdir()
    (outside_root / "secret.txt").write_bytes(b"secret")
    (share_root / "inside.txt").write_bytes(b"inside")
    try:
        (share_root / "escape").symlink_to(
            outside_root / "secret.txt"
        )
        (share_root / "contained").symlink_to(
            share_root / "inside.txt"
        )
        (share_root / "escape-dir").symlink_to(
            outside_root, target_is_directory=True
        )
    except (NotImplementedError, OSError) as error:
        pytest.skip("symlink creation is unavailable: {}".format(error))

    backend = LocalFilesystemBackend({"data": share_root})

    with pytest.raises(InvalidPathError):
        await backend.stat("data", "escape")
    with pytest.raises(InvalidPathError):
        await backend.open("data", "escape", "rb")
    with pytest.raises(InvalidPathError):
        await backend.open("data", "escape-dir/new.txt", "x+b")
    with pytest.raises(InvalidPathError):
        await backend.open("data", "", "rb", delete_on_close=True)

    handle = await backend.open("DATA", "contained", "rb")
    try:
        assert await backend.read(handle, 0, 32) == b"inside"
    finally:
        await backend.close(handle)


@pytest.mark.asyncio
async def test_local_backend_crud_and_open_handle_rename(
    tmp_path: Path,
) -> None:
    backend = LocalFilesystemBackend({"Data": tmp_path})

    await backend.mkdir("data", "folder")
    handle = await backend.open(
        "DATA",
        "folder/source.bin",
        "x+b",
        desired_access=0x03,
        share_access=0x07,
        create_options=0x40,
    )
    assert await backend.write(handle, 0, b"hello") == 5
    assert await backend.write(handle.file_id, 5, b" world") == 6
    await backend.flush(handle)
    assert await backend.read(handle, 0, 64) == b"hello world"
    assert await backend.truncate(handle, 5) == 5
    assert (await backend.stat_handle(handle)).st_size == 5

    destination = await backend.rename(
        "Data", "folder/source.bin", "folder/renamed.bin"
    )
    assert destination == tmp_path / "folder" / "renamed.bin"
    assert handle.local_path == destination
    assert handle.relative_path == Path("folder/renamed.bin")
    assert await backend.read(handle, 0, 16) == b"hello"

    entries = await backend.list("data", "folder")
    assert [(entry.name, entry.object_type) for entry in entries] == [
        ("renamed.bin", FilesystemObjectType.FILE)
    ]
    await backend.close(handle)
    assert (await backend.stat("Data", "folder/renamed.bin")).st_size == 5

    await backend.unlink("data", "folder/renamed.bin")
    await backend.rmdir("data", "folder")
    assert await backend.list("data") == []


@pytest.mark.asyncio
async def test_handles_have_unique_128_bit_ids_and_per_open_state(
    tmp_path: Path,
) -> None:
    file_path = tmp_path / "item.bin"
    file_path.write_bytes(b"item")
    backend = LocalFilesystemBackend({"data": tmp_path})

    first = await backend.open(
        "data",
        "item.bin",
        "r+b",
        desired_access=0x0012019F,
        share_access=0x07,
        create_options=0x40,
        session_id=9,
        tree_id=12,
    )
    second = await backend.open("data", "item.bin", "rb")
    try:
        assert first.file_id != second.file_id
        assert 0 < first.file_id < (1 << 128)
        assert 0 < second.file_id < (1 << 128)
        first_parts = SMBFileId.from_int(first.file_id)
        second_parts = SMBFileId.from_int(second.file_id)
        assert first_parts.to_int() == first.file_id
        assert first_parts.persistent == second_parts.persistent
        assert first_parts.volatile != second_parts.volatile

        assert first.desired_access == 0x0012019F
        assert first.share_access == 0x07
        assert first.create_options == 0x40
        assert first.object_type is FilesystemObjectType.FILE
        assert first.delete_on_close is False
        assert first.session_id == 9
        assert first.tree_id == 12
        assert first.enumeration_state.pattern == "*"
        assert first.enumeration_state.index == 0
    finally:
        await backend.close_all()


@pytest.mark.asyncio
async def test_close_all_is_deterministic_and_honors_delete_on_close(
    tmp_path: Path,
) -> None:
    backend = LocalFilesystemBackend({"data": tmp_path})
    delete_handle = await backend.open(
        "data", "delete.bin", "x+b", delete_on_close=True
    )
    keep_handle = await backend.open("data", "keep.bin", "x+b")
    delete_file = delete_handle.file_object
    keep_file = keep_handle.file_object

    closed_ids = await backend.close_all()

    assert closed_ids == sorted([delete_handle.file_id, keep_handle.file_id])
    assert backend.active_file_ids == []
    assert delete_handle.closed is True
    assert keep_handle.closed is True
    assert delete_file is not None and delete_file.closed is True
    assert keep_file is not None and keep_file.closed is True
    assert not (tmp_path / "delete.bin").exists()
    assert (tmp_path / "keep.bin").exists()
    assert await backend.close_all() == []
    with pytest.raises(InvalidHandleError):
        backend.get_handle(delete_handle.file_id)


@pytest.mark.asyncio
async def test_filesystem_calls_run_outside_the_event_loop_thread(
    tmp_path: Path,
) -> None:
    worker_threads = []

    class TrackingBackend(LocalFilesystemBackend):
        @staticmethod
        def _stat_sync(share: ShareConfig, path: str) -> object:
            worker_threads.append(threading.get_ident())
            return LocalFilesystemBackend._stat_sync(share, path)

    event_loop_thread = threading.get_ident()
    backend = TrackingBackend({"data": tmp_path})

    await backend.stat("data")

    assert worker_threads
    assert worker_threads[0] != event_loop_thread


def test_filesystem_module_uses_python38_compatible_annotations() -> None:
    source_path = (
        Path(__file__).parents[2]
        / "aiosmb"
        / "server"
        / "filesystem.py"
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
