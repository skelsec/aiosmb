"""Asynchronous, share-contained storage backends for the SMB server.

The protocol layer should deal in share-relative paths and ``FileHandle``
instances only.  Local filesystem calls are kept behind this module so they
can run in an executor without blocking the server's event loop.
"""

import abc
import asyncio
import functools
import hashlib
import itertools
import os
import stat as stat_module
import threading
from concurrent.futures import Executor
from dataclasses import dataclass, field, replace
from enum import Enum
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import (
    Any,
    BinaryIO,
    Callable,
    Dict,
    List,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
    Union,
)


_UINT64_MASK = (1 << 64) - 1
_UINT128_LIMIT = 1 << 128
_FILE_ID_COUNTER = itertools.count(1)
_FILE_ID_LOCK = threading.Lock()


class FilesystemBackendError(Exception):
    """Base class for storage-boundary failures."""


class ShareNotFoundError(FilesystemBackendError):
    """Raised when a requested share is not configured."""


class InvalidPathError(FilesystemBackendError, ValueError):
    """Raised when a client path is unsafe or leaves its share."""


class InvalidHandleError(FilesystemBackendError):
    """Raised when a file ID is unknown or no longer open."""


class HandleTypeError(FilesystemBackendError):
    """Raised when an operation is invalid for the handle's object type."""


class ReadOnlyShareError(FilesystemBackendError, PermissionError):
    """Raised when a mutating operation targets a read-only share."""


class FilesystemCleanupError(FilesystemBackendError):
    """Reports cleanup failures after all handles have been attempted."""

    def __init__(
        self,
        closed_file_ids: Sequence[int],
        errors: Sequence[BaseException],
    ) -> None:
        self.closed_file_ids = list(closed_file_ids)
        self.errors = list(errors)
        super().__init__(
            "failed to clean up {} filesystem handle(s)".format(len(errors))
        )


class FilesystemObjectType(Enum):
    FILE = "file"
    DIRECTORY = "directory"
    SYMLINK = "symlink"
    OTHER = "other"


class HandleLifecycle(Enum):
    OPEN = "open"
    CLOSING = "closing"
    CLOSED = "closed"


@dataclass(frozen=True)
class ShareMetadata:
    """Protocol-facing information about a configured disk share."""

    name: str
    remark: str = ""
    read_only: bool = False


@dataclass(frozen=True)
class ShareConfig:
    """Configuration for one local disk share."""

    name: str
    root: Path
    remark: str = ""
    read_only: bool = False

    def __post_init__(self) -> None:
        name = str(self.name)
        if not name or "\x00" in name or "/" in name or "\\" in name:
            raise ValueError("share names must be non-empty path components")
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "root", Path(self.root).expanduser())

    @property
    def metadata(self) -> ShareMetadata:
        return ShareMetadata(
            name=self.name,
            remark=self.remark,
            read_only=self.read_only,
        )


@dataclass(frozen=True)
class SMBFileId:
    """The persistent/volatile halves of an SMB2 128-bit FILEID."""

    persistent: int
    volatile: int

    def __post_init__(self) -> None:
        if not 0 <= self.persistent <= _UINT64_MASK:
            raise ValueError("persistent file ID must fit in 64 bits")
        if not 0 <= self.volatile <= _UINT64_MASK:
            raise ValueError("volatile file ID must fit in 64 bits")

    def to_int(self) -> int:
        return self.persistent | (self.volatile << 64)

    @classmethod
    def from_int(cls, value: int) -> "SMBFileId":
        if not isinstance(value, int) or not 0 <= value < _UINT128_LIMIT:
            raise ValueError("SMB file ID must be an unsigned 128-bit integer")
        return cls(
            persistent=value & _UINT64_MASK,
            volatile=(value >> 64) & _UINT64_MASK,
        )


@dataclass(frozen=True)
class DirectoryEntry:
    """A stable directory-listing result without a live ``os.DirEntry``."""

    name: str
    relative_path: Path
    stat: os.stat_result
    object_type: FilesystemObjectType


@dataclass
class DirectoryEnumerationState:
    """Cursor state retained independently for each open directory."""

    entries: List[DirectoryEntry] = field(default_factory=list)
    index: int = 0
    pattern: str = "*"
    information_class: Any = None

    def reset(
        self,
        entries: Sequence[DirectoryEntry],
        pattern: str = "*",
        information_class: Any = None,
    ) -> None:
        self.entries = list(entries)
        self.index = 0
        self.pattern = pattern
        self.information_class = information_class


@dataclass
class FileHandle:
    """Server-side state for one SMB open."""

    file_id: int
    share: ShareConfig
    relative_path: Path
    local_path: Path
    object_type: FilesystemObjectType
    desired_access: int = 0
    share_access: int = 0
    create_options: int = 0
    delete_on_close: bool = False
    session_id: Optional[int] = None
    tree_id: Optional[int] = None
    enumeration_state: DirectoryEnumerationState = field(
        default_factory=DirectoryEnumerationState
    )
    file_object: Optional[BinaryIO] = field(
        default=None, repr=False, compare=False
    )
    lifecycle: HandleLifecycle = HandleLifecycle.OPEN
    closed: bool = False
    _io_lock: threading.RLock = field(
        default_factory=threading.RLock, repr=False, compare=False
    )

    @property
    def file_id_parts(self) -> SMBFileId:
        return SMBFileId.from_int(self.file_id)

    @property
    def handle(self) -> Optional[BinaryIO]:
        """Compatibility alias for the legacy server ``FileEntry``."""

        return self.file_object

    @property
    def path(self) -> Path:
        """Compatibility alias for the legacy server ``FileEntry``."""

        return self.local_path

    @property
    def enumeration(self) -> DirectoryEnumerationState:
        return self.enumeration_state


@dataclass
class TreeState:
    """Filesystem state owned by one SMB tree connection."""

    tree_id: int
    share: ShareConfig
    handles: Dict[int, FileHandle] = field(default_factory=dict)
    connected: bool = True

    def add_handle(self, handle: FileHandle) -> None:
        if handle.file_id in self.handles:
            raise ValueError("duplicate file ID in tree")
        handle.tree_id = self.tree_id
        self.handles[handle.file_id] = handle

    def remove_handle(self, file_id: int) -> FileHandle:
        try:
            return self.handles.pop(file_id)
        except KeyError:
            raise InvalidHandleError("unknown file ID {}".format(file_id))

    def file_ids(self) -> List[int]:
        return sorted(self.handles)


@dataclass
class SessionState:
    """Filesystem state owned by one authenticated SMB session."""

    session_id: int
    trees: Dict[int, TreeState] = field(default_factory=dict)
    active: bool = True

    def add_tree(self, tree: TreeState) -> None:
        if tree.tree_id in self.trees:
            raise ValueError("duplicate tree ID in session")
        self.trees[tree.tree_id] = tree

    def remove_tree(self, tree_id: int) -> TreeState:
        try:
            tree = self.trees.pop(tree_id)
        except KeyError:
            raise ShareNotFoundError("unknown tree ID {}".format(tree_id))
        tree.connected = False
        return tree


ShareSource = Any
ShareReference = Union[str, ShareConfig]
HandleReference = Union[int, FileHandle]


def normalize_relative_path(path: Any) -> Path:
    """Normalize an SMB path while rejecting rooted and parent paths."""

    if path is None:
        return Path(".")
    try:
        raw_path = os.fspath(path)
    except TypeError:
        raise InvalidPathError("path must be a string or path-like object")
    if isinstance(raw_path, bytes):
        raise InvalidPathError("byte paths are not accepted from SMB clients")
    if "\x00" in raw_path:
        raise InvalidPathError("NUL is not allowed in SMB paths")

    normalized = raw_path.replace("\\", "/")
    windows_path = PureWindowsPath(raw_path)
    posix_path = PurePosixPath(normalized)
    if (
        windows_path.drive
        or windows_path.root
        or posix_path.is_absolute()
        or normalized.startswith("/")
    ):
        raise InvalidPathError("absolute SMB paths are not allowed")

    parts = []
    for part in normalized.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            raise InvalidPathError("parent traversal is not allowed")
        parts.append(part)
    if not parts:
        return Path(".")
    return Path(*parts)


def normalize_shares(source: ShareSource) -> Dict[str, ShareConfig]:
    """Normalize ``settings.shares`` without breaking ``str -> path`` maps.

    Values may be legacy strings/path-like objects, ``ShareConfig`` instances,
    or mappings with ``root``/``path``, ``remark``, and ``read_only`` keys.
    Returned keys preserve configured spelling; lookup in the local backend is
    case-insensitive.
    """

    shares = source
    if not isinstance(shares, Mapping):
        shares = getattr(source, "shares", None)
    if not isinstance(shares, Mapping):
        raise TypeError("shares must be a mapping or an object with .shares")

    result = {}
    seen_names = {}
    for configured_name, value in shares.items():
        name = str(configured_name)
        folded_name = name.casefold()
        if folded_name in seen_names:
            raise ValueError(
                "share names differ only by case: {!r} and {!r}".format(
                    seen_names[folded_name], name
                )
            )

        if isinstance(value, ShareConfig):
            config = value
            if config.name != name:
                config = replace(config, name=name)
        elif isinstance(value, Mapping):
            root = value.get("root", value.get("path"))
            if root is None:
                raise ValueError("share {!r} has no root/path".format(name))
            config = ShareConfig(
                name=name,
                root=Path(root),
                remark=str(value.get("remark", "")),
                read_only=bool(value.get("read_only", False)),
            )
        else:
            try:
                root = Path(value)
            except TypeError:
                raise TypeError(
                    "share {!r} must map to a path or ShareConfig".format(name)
                )
            config = ShareConfig(name=name, root=root)

        result[name] = config
        seen_names[folded_name] = name
    return result


class FilesystemBackend(abc.ABC):
    """Abstract asynchronous storage contract consumed by the SMB server."""

    @property
    @abc.abstractmethod
    def shares(self) -> Mapping[str, ShareConfig]:
        raise NotImplementedError()

    @abc.abstractmethod
    def get_share(self, share: ShareReference) -> ShareConfig:
        raise NotImplementedError()

    @abc.abstractmethod
    async def resolve_path(
        self, share: ShareReference, path: Any = ""
    ) -> Path:
        raise NotImplementedError()

    @abc.abstractmethod
    async def stat(
        self, share: ShareReference, path: Any = ""
    ) -> os.stat_result:
        raise NotImplementedError()

    @abc.abstractmethod
    async def list(
        self, share: ShareReference, path: Any = ""
    ) -> List[DirectoryEntry]:
        raise NotImplementedError()

    @abc.abstractmethod
    async def open(
        self,
        share: ShareReference,
        path: Any,
        mode: str = "rb",
        desired_access: int = 0,
        share_access: int = 0,
        create_options: int = 0,
        delete_on_close: bool = False,
        object_type: Optional[FilesystemObjectType] = None,
        session_id: Optional[int] = None,
        tree_id: Optional[int] = None,
    ) -> FileHandle:
        raise NotImplementedError()

    @abc.abstractmethod
    async def read(
        self, handle: HandleReference, offset: int, length: int
    ) -> bytes:
        raise NotImplementedError()

    @abc.abstractmethod
    async def write(
        self, handle: HandleReference, offset: int, data: bytes
    ) -> int:
        raise NotImplementedError()

    @abc.abstractmethod
    async def flush(self, handle: HandleReference) -> None:
        raise NotImplementedError()

    @abc.abstractmethod
    async def truncate(self, handle: HandleReference, size: int) -> int:
        raise NotImplementedError()

    @abc.abstractmethod
    async def rename(
        self,
        share: ShareReference,
        source: Any,
        destination: Any,
        replace_existing: bool = False,
    ) -> Path:
        raise NotImplementedError()

    @abc.abstractmethod
    async def unlink(self, share: ShareReference, path: Any) -> None:
        raise NotImplementedError()

    @abc.abstractmethod
    async def mkdir(
        self,
        share: ShareReference,
        path: Any,
        parents: bool = False,
        exist_ok: bool = False,
    ) -> None:
        raise NotImplementedError()

    @abc.abstractmethod
    async def rmdir(self, share: ShareReference, path: Any) -> None:
        raise NotImplementedError()

    @abc.abstractmethod
    async def close(self, handle: HandleReference) -> None:
        raise NotImplementedError()

    @abc.abstractmethod
    async def close_all(self) -> List[int]:
        raise NotImplementedError()


class LocalFilesystemBackend(FilesystemBackend):
    """Executor-backed filesystem rooted beneath configured local shares."""

    def __init__(
        self,
        shares: ShareSource,
        executor: Optional[Executor] = None,
    ) -> None:
        normalized = normalize_shares(shares)
        configured = {}
        lookup = {}
        for name, config in normalized.items():
            try:
                root = config.root.resolve(strict=True)
            except (OSError, RuntimeError) as error:
                raise ValueError(
                    "share {!r} root cannot be resolved: {}".format(
                        name, error
                    )
                )
            if not root.is_dir():
                raise ValueError(
                    "share {!r} root is not a directory".format(name)
                )
            canonical = replace(config, root=root)
            configured[name] = canonical
            lookup[name.casefold()] = canonical

        self._shares = configured
        self._share_lookup = lookup
        self._executor = executor
        self._handles = {}  # type: Dict[int, FileHandle]
        self._delete_pending = set()  # type: Set[Path]
        self._lifecycle_lock = asyncio.Lock()

    @property
    def shares(self) -> Mapping[str, ShareConfig]:
        return dict(self._shares)

    @property
    def active_file_ids(self) -> List[int]:
        return sorted(self._handles)

    def get_share(self, share: ShareReference) -> ShareConfig:
        name = share.name if isinstance(share, ShareConfig) else str(share)
        try:
            return self._share_lookup[name.casefold()]
        except KeyError:
            raise ShareNotFoundError("unknown share {!r}".format(name))

    def get_handle(self, handle: HandleReference) -> FileHandle:
        file_id = handle.file_id if isinstance(handle, FileHandle) else handle
        try:
            active = self._handles[file_id]
        except (KeyError, TypeError):
            raise InvalidHandleError("unknown file ID {!r}".format(file_id))
        if isinstance(handle, FileHandle) and active is not handle:
            raise InvalidHandleError("file handle does not belong to backend")
        if active.lifecycle is not HandleLifecycle.OPEN or active.closed:
            raise InvalidHandleError("file ID {} is not open".format(file_id))
        return active

    async def _run_sync(
        self, function: Callable[..., Any], *args: Any
    ) -> Any:
        loop = asyncio.get_running_loop()
        call = functools.partial(function, *args)
        return await loop.run_in_executor(self._executor, call)

    @staticmethod
    def _assert_contained(root: Path, candidate: Path) -> None:
        try:
            candidate.relative_to(root)
        except ValueError:
            raise InvalidPathError(
                "path {!s} escapes share root {!s}".format(candidate, root)
            )

    @classmethod
    def _resolve_sync(cls, share: ShareConfig, path: Any) -> Path:
        relative = normalize_relative_path(path)
        try:
            candidate = (share.root / relative).resolve(strict=False)
        except (OSError, RuntimeError) as error:
            raise InvalidPathError("path cannot be resolved: {}".format(error))
        cls._assert_contained(share.root, candidate)
        return candidate

    @classmethod
    def _resolve_leaf_sync(
        cls, share: ShareConfig, path: Any
    ) -> Tuple[Path, Path]:
        relative = normalize_relative_path(path)
        if relative == Path("."):
            raise InvalidPathError("the share root cannot be modified")
        parent_relative = Path(*relative.parts[:-1])
        parent = cls._resolve_sync(share, parent_relative)
        candidate = parent / relative.name
        try:
            resolved_candidate = candidate.resolve(strict=False)
        except (OSError, RuntimeError) as error:
            raise InvalidPathError("path cannot be resolved: {}".format(error))
        cls._assert_contained(share.root, resolved_candidate)
        return candidate, relative

    async def resolve_path(
        self, share: ShareReference, path: Any = ""
    ) -> Path:
        config = self.get_share(share)
        return await self._run_sync(self._resolve_sync, config, path)

    @staticmethod
    def _stat_sync(share: ShareConfig, path: Any) -> os.stat_result:
        location = LocalFilesystemBackend._resolve_sync(share, path)
        return location.stat()

    async def stat(
        self, share: ShareReference, path: Any = ""
    ) -> os.stat_result:
        config = self.get_share(share)
        return await self._run_sync(self._stat_sync, config, path)

    @staticmethod
    def _object_type(mode: int) -> FilesystemObjectType:
        if stat_module.S_ISREG(mode):
            return FilesystemObjectType.FILE
        if stat_module.S_ISDIR(mode):
            return FilesystemObjectType.DIRECTORY
        if stat_module.S_ISLNK(mode):
            return FilesystemObjectType.SYMLINK
        return FilesystemObjectType.OTHER

    @classmethod
    def _list_sync(
        cls, share: ShareConfig, path: Any
    ) -> List[DirectoryEntry]:
        relative = normalize_relative_path(path)
        location = cls._resolve_sync(share, relative)
        entries = []
        with os.scandir(str(location)) as iterator:
            for entry in iterator:
                entry_stat = entry.stat(follow_symlinks=False)
                child_relative = (
                    Path(entry.name)
                    if relative == Path(".")
                    else relative / entry.name
                )
                entries.append(
                    DirectoryEntry(
                        name=entry.name,
                        relative_path=child_relative,
                        stat=entry_stat,
                        object_type=cls._object_type(entry_stat.st_mode),
                    )
                )
        entries.sort(key=lambda item: (item.name.casefold(), item.name))
        return entries

    async def list(
        self, share: ShareReference, path: Any = ""
    ) -> List[DirectoryEntry]:
        config = self.get_share(share)
        return await self._run_sync(self._list_sync, config, path)

    async def listdir(
        self, share: ShareReference, path: Any = ""
    ) -> List[DirectoryEntry]:
        return await self.list(share, path)

    async def list_directory(
        self, share: ShareReference, path: Any = ""
    ) -> List[DirectoryEntry]:
        return await self.list(share, path)

    @classmethod
    def _open_sync(
        cls,
        share: ShareConfig,
        path: Any,
        mode: str,
        expected_type: Optional[FilesystemObjectType],
    ) -> Tuple[Path, Path, FilesystemObjectType, Optional[BinaryIO], os.stat_result]:
        if "b" not in mode:
            raise ValueError("filesystem backend handles must use binary mode")
        relative = normalize_relative_path(path)
        location = cls._resolve_sync(share, relative)

        try:
            before_stat = location.stat()
        except FileNotFoundError:
            before_stat = None

        if before_stat is not None and stat_module.S_ISDIR(before_stat.st_mode):
            actual_type = FilesystemObjectType.DIRECTORY
            if expected_type not in (None, FilesystemObjectType.DIRECTORY):
                raise IsADirectoryError(str(location))
            return relative, location, actual_type, None, before_stat
        if expected_type is FilesystemObjectType.DIRECTORY:
            if before_stat is None:
                raise FileNotFoundError(str(location))
            raise NotADirectoryError(str(location))

        file_object = open(str(location), mode)
        try:
            opened_stat = os.fstat(file_object.fileno())
            actual_type = cls._object_type(opened_stat.st_mode)
            if actual_type is not FilesystemObjectType.FILE:
                raise HandleTypeError(
                    "opened object is not a regular file: {!s}".format(location)
                )
            return (
                relative,
                location,
                actual_type,
                file_object,
                opened_stat,
            )
        except BaseException:
            file_object.close()
            raise

    @staticmethod
    def _persistent_id(stat_result: os.stat_result) -> int:
        identity = "{}:{}".format(
            int(getattr(stat_result, "st_dev", 0)),
            int(getattr(stat_result, "st_ino", 0)),
        ).encode("ascii")
        persistent = int.from_bytes(
            hashlib.blake2b(identity, digest_size=8).digest(), "little"
        )
        return persistent or 1

    @staticmethod
    def _allocate_file_id(stat_result: os.stat_result) -> int:
        with _FILE_ID_LOCK:
            volatile = next(_FILE_ID_COUNTER)
        if volatile > _UINT64_MASK:
            raise OverflowError("SMB volatile file ID space exhausted")
        return SMBFileId(
            persistent=LocalFilesystemBackend._persistent_id(stat_result),
            volatile=volatile,
        ).to_int()

    @staticmethod
    def _mode_mutates(mode: str) -> bool:
        return any(flag in mode for flag in ("+", "w", "a", "x"))

    async def open(
        self,
        share: ShareReference,
        path: Any,
        mode: str = "rb",
        desired_access: int = 0,
        share_access: int = 0,
        create_options: int = 0,
        delete_on_close: bool = False,
        object_type: Optional[FilesystemObjectType] = None,
        session_id: Optional[int] = None,
        tree_id: Optional[int] = None,
    ) -> FileHandle:
        config = self.get_share(share)
        if (
            delete_on_close
            and normalize_relative_path(path) == Path(".")
        ):
            raise InvalidPathError(
                "the share root cannot be marked delete-on-close"
            )
        if config.read_only and (
            self._mode_mutates(mode) or delete_on_close
        ):
            raise ReadOnlyShareError(
                "share {!r} is read-only".format(config.name)
            )

        (
            relative,
            location,
            actual_type,
            file_object,
            opened_stat,
        ) = await self._run_sync(
            self._open_sync, config, path, mode, object_type
        )
        handle = FileHandle(
            file_id=self._allocate_file_id(opened_stat),
            share=config,
            relative_path=relative,
            local_path=location,
            object_type=actual_type,
            desired_access=int(desired_access),
            share_access=int(share_access),
            create_options=int(create_options),
            delete_on_close=bool(delete_on_close),
            session_id=session_id,
            tree_id=tree_id,
            file_object=file_object,
        )

        try:
            async with self._lifecycle_lock:
                self._handles[handle.file_id] = handle
        except BaseException:
            if file_object is not None:
                await self._run_sync(file_object.close)
            handle.lifecycle = HandleLifecycle.CLOSED
            handle.closed = True
            raise
        return handle

    @staticmethod
    def _require_file(handle: FileHandle) -> BinaryIO:
        if (
            handle.lifecycle is not HandleLifecycle.OPEN
            or handle.closed
            or handle.file_object is None
        ):
            if handle.object_type is FilesystemObjectType.DIRECTORY:
                raise HandleTypeError("operation requires a file handle")
            raise InvalidHandleError(
                "file ID {} is not open".format(handle.file_id)
            )
        return handle.file_object

    @classmethod
    def _read_sync(
        cls, handle: FileHandle, offset: int, length: int
    ) -> bytes:
        with handle._io_lock:
            file_object = cls._require_file(handle)
            file_object.seek(offset)
            data = file_object.read(length)
            if not isinstance(data, bytes):
                data = bytes(data)
            return data

    async def read(
        self, handle: HandleReference, offset: int, length: int
    ) -> bytes:
        if offset < 0 or length < 0:
            raise ValueError("read offset and length must be non-negative")
        active = self.get_handle(handle)
        return await self._run_sync(
            self._read_sync, active, offset, length
        )

    @classmethod
    def _write_sync(
        cls, handle: FileHandle, offset: int, data: bytes
    ) -> int:
        with handle._io_lock:
            file_object = cls._require_file(handle)
            file_object.seek(offset)
            written = file_object.write(data)
            return len(data) if written is None else int(written)

    async def write(
        self, handle: HandleReference, offset: int, data: bytes
    ) -> int:
        if offset < 0:
            raise ValueError("write offset must be non-negative")
        active = self.get_handle(handle)
        if active.share.read_only:
            raise ReadOnlyShareError(
                "share {!r} is read-only".format(active.share.name)
            )
        payload = bytes(data)
        return await self._run_sync(
            self._write_sync, active, offset, payload
        )

    @classmethod
    def _flush_sync(cls, handle: FileHandle) -> None:
        with handle._io_lock:
            file_object = cls._require_file(handle)
            file_object.flush()
            os.fsync(file_object.fileno())

    async def flush(self, handle: HandleReference) -> None:
        active = self.get_handle(handle)
        await self._run_sync(self._flush_sync, active)

    @classmethod
    def _truncate_sync(cls, handle: FileHandle, size: int) -> int:
        with handle._io_lock:
            file_object = cls._require_file(handle)
            file_object.truncate(size)
            return size

    async def truncate(self, handle: HandleReference, size: int) -> int:
        if size < 0:
            raise ValueError("truncate size must be non-negative")
        active = self.get_handle(handle)
        if active.share.read_only:
            raise ReadOnlyShareError(
                "share {!r} is read-only".format(active.share.name)
            )
        return await self._run_sync(self._truncate_sync, active, size)

    @classmethod
    def _stat_handle_sync(cls, handle: FileHandle) -> os.stat_result:
        with handle._io_lock:
            if (
                handle.lifecycle is not HandleLifecycle.OPEN
                or handle.closed
            ):
                raise InvalidHandleError(
                    "file ID {} is not open".format(handle.file_id)
                )
            if handle.file_object is not None:
                return os.fstat(handle.file_object.fileno())
            return handle.local_path.stat()

    async def stat_handle(
        self, handle: HandleReference
    ) -> os.stat_result:
        active = self.get_handle(handle)
        return await self._run_sync(self._stat_handle_sync, active)

    @classmethod
    def _rename_sync(
        cls,
        share: ShareConfig,
        source: Any,
        destination: Any,
        replace_existing: bool,
    ) -> Tuple[Path, Path, Path, Path]:
        source_path, source_relative = cls._resolve_leaf_sync(share, source)
        destination_path, destination_relative = cls._resolve_leaf_sync(
            share, destination
        )
        if not replace_existing and destination_path.exists():
            raise FileExistsError(str(destination_path))
        if replace_existing:
            os.replace(str(source_path), str(destination_path))
        else:
            os.rename(str(source_path), str(destination_path))
        return (
            source_path,
            destination_path,
            source_relative,
            destination_relative,
        )

    async def rename(
        self,
        share: ShareReference,
        source: Any,
        destination: Any,
        replace_existing: bool = False,
    ) -> Path:
        config = self.get_share(share)
        if config.read_only:
            raise ReadOnlyShareError(
                "share {!r} is read-only".format(config.name)
            )
        async with self._lifecycle_lock:
            (
                source_path,
                destination_path,
                source_relative,
                destination_relative,
            ) = await self._run_sync(
                self._rename_sync,
                config,
                source,
                destination,
                replace_existing,
            )
            for handle in self._handles.values():
                if handle.share.name.casefold() != config.name.casefold():
                    continue
                try:
                    path_suffix = handle.local_path.relative_to(source_path)
                except ValueError:
                    continue
                try:
                    relative_suffix = handle.relative_path.relative_to(
                        source_relative
                    )
                except ValueError:
                    relative_suffix = path_suffix
                handle.local_path = destination_path / path_suffix
                handle.relative_path = destination_relative / relative_suffix

            pending_updates = []
            for pending in self._delete_pending:
                try:
                    suffix = pending.relative_to(source_path)
                except ValueError:
                    continue
                pending_updates.append((pending, destination_path / suffix))
            for old_path, new_path in pending_updates:
                self._delete_pending.remove(old_path)
                self._delete_pending.add(new_path)
        return destination_path

    @classmethod
    def _unlink_sync(cls, share: ShareConfig, path: Any) -> None:
        location, _ = cls._resolve_leaf_sync(share, path)
        location.unlink()

    async def unlink(self, share: ShareReference, path: Any) -> None:
        config = self.get_share(share)
        if config.read_only:
            raise ReadOnlyShareError(
                "share {!r} is read-only".format(config.name)
            )
        await self._run_sync(self._unlink_sync, config, path)

    @classmethod
    def _mkdir_sync(
        cls,
        share: ShareConfig,
        path: Any,
        parents: bool,
        exist_ok: bool,
    ) -> None:
        location, _ = cls._resolve_leaf_sync(share, path)
        location.mkdir(parents=parents, exist_ok=exist_ok)

    async def mkdir(
        self,
        share: ShareReference,
        path: Any,
        parents: bool = False,
        exist_ok: bool = False,
    ) -> None:
        config = self.get_share(share)
        if config.read_only:
            raise ReadOnlyShareError(
                "share {!r} is read-only".format(config.name)
            )
        await self._run_sync(
            self._mkdir_sync, config, path, parents, exist_ok
        )

    @classmethod
    def _rmdir_sync(cls, share: ShareConfig, path: Any) -> None:
        location, _ = cls._resolve_leaf_sync(share, path)
        location.rmdir()

    async def rmdir(self, share: ShareReference, path: Any) -> None:
        config = self.get_share(share)
        if config.read_only:
            raise ReadOnlyShareError(
                "share {!r} is read-only".format(config.name)
            )
        await self._run_sync(self._rmdir_sync, config, path)

    @staticmethod
    def _close_file_sync(handle: FileHandle) -> None:
        with handle._io_lock:
            try:
                if handle.file_object is not None:
                    handle.file_object.close()
            finally:
                handle.lifecycle = HandleLifecycle.CLOSED
                handle.closed = True

    @staticmethod
    def _delete_sync(
        path: Path, object_type: FilesystemObjectType
    ) -> None:
        try:
            if object_type is FilesystemObjectType.DIRECTORY:
                path.rmdir()
            else:
                path.unlink()
        except FileNotFoundError:
            return

    async def _close_locked(self, handle: FileHandle) -> None:
        self._handles.pop(handle.file_id, None)
        handle.lifecycle = HandleLifecycle.CLOSING
        errors = []
        try:
            await self._run_sync(self._close_file_sync, handle)
        except Exception as error:
            errors.append(error)

        if handle.delete_on_close:
            self._delete_pending.add(handle.local_path)
        has_other_opens = any(
            other.local_path == handle.local_path
            for other in self._handles.values()
        )
        if (
            handle.local_path in self._delete_pending
            and not has_other_opens
        ):
            try:
                await self._run_sync(
                    self._delete_sync,
                    handle.local_path,
                    handle.object_type,
                )
                self._delete_pending.remove(handle.local_path)
            except Exception as error:
                errors.append(error)
        if errors:
            raise FilesystemCleanupError([handle.file_id], errors)

    async def close(self, handle: HandleReference) -> None:
        async with self._lifecycle_lock:
            active = self.get_handle(handle)
            await self._close_locked(active)

    async def close_all(self) -> List[int]:
        closed_file_ids = []
        errors = []
        async with self._lifecycle_lock:
            for file_id in sorted(self._handles):
                handle = self._handles.get(file_id)
                if handle is None:
                    continue
                try:
                    await self._close_locked(handle)
                except Exception as error:
                    errors.append(error)
                closed_file_ids.append(file_id)
        if errors:
            raise FilesystemCleanupError(closed_file_ids, errors)
        return closed_file_ids

    async def aclose(self) -> List[int]:
        return await self.close_all()

    async def __aenter__(self) -> "LocalFilesystemBackend":
        return self

    async def __aexit__(
        self,
        exception_type: Any,
        exception: Any,
        traceback: Any,
    ) -> None:
        await self.close_all()


OpenHandle = FileHandle


__all__ = [
    "DirectoryEntry",
    "DirectoryEnumerationState",
    "FileHandle",
    "FilesystemBackend",
    "FilesystemBackendError",
    "FilesystemCleanupError",
    "FilesystemObjectType",
    "HandleLifecycle",
    "HandleTypeError",
    "InvalidHandleError",
    "InvalidPathError",
    "LocalFilesystemBackend",
    "OpenHandle",
    "ReadOnlyShareError",
    "SMBFileId",
    "SessionState",
    "ShareConfig",
    "ShareMetadata",
    "ShareNotFoundError",
    "TreeState",
    "normalize_relative_path",
    "normalize_shares",
]
