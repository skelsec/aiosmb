"""Live file, directory, transfer, security, and concurrency coverage."""

import asyncio
import hashlib
import sys
import uuid

import pytest

if sys.version_info < (3, 9):
    pytest.skip("blocked by KF-0107", allow_module_level=True)

from aiosmb.commons.interfaces.directory import SMBDirectory
from aiosmb.commons.interfaces.file import SMBFile

from ._lab import logged_in


pytestmark = [
    pytest.mark.samba,
    pytest.mark.asyncio,
    pytest.mark.destructive,
]


def _unique_name(prefix, suffix=""):
    return "{}-{}{}".format(prefix, uuid.uuid4().hex, suffix)


def _assert_success(result, error, operation):
    assert error is None, "{} failed with {}".format(
        operation, type(error).__name__
    )
    assert result is not False


async def _write_file(connection, unc_path, payload):
    remote_file = SMBFile.from_uncpath(unc_path)
    opened, error = await remote_file.open(connection, mode="w")
    _assert_success(opened, error, "file open for write")
    try:
        written, error = await remote_file.write(payload)
        _assert_success(written, error, "file write")
        assert written == len(payload)
    finally:
        await remote_file.close()


async def _read_file(connection, unc_path, chunk_size=512 * 1024):
    remote_file = SMBFile.from_uncpath(unc_path)
    opened, error = await remote_file.open(connection, mode="r")
    _assert_success(opened, error, "file open for read")
    chunks = []
    try:
        while True:
            chunk, error = await remote_file.read(chunk_size)
            _assert_success(chunk, error, "file read")
            if chunk == b"":
                break
            chunks.append(chunk)
    finally:
        await remote_file.close()
    return b"".join(chunks)


async def _delete_file(connection, unc_path):
    deleted, error = await SMBFile.delete_unc(connection, unc_path)
    _assert_success(deleted, error, "file cleanup")


@pytest.mark.capability("directory_crud", "file_crud")
async def test_directory_and_file_crud(samba_destructive_profile):
    profile = samba_destructive_profile
    profile.require_capability("directory_crud")
    profile.require_capability("file_crud")
    directory_name = _unique_name("crud")
    file_name = "round-trip.bin"
    directory_unc = profile.unc_path(directory_name)
    file_unc = profile.unc_path(directory_name, file_name)

    async with logged_in(profile) as connection:
        created, error = await SMBDirectory.create_remote(
            connection, profile.remote_path(directory_name)
        )
        _assert_success(created, error, "directory create")
        try:
            payload = b"aiosmb-samba-crud\x00\xff"
            await _write_file(connection, file_unc, payload)
            assert await _read_file(connection, file_unc) == payload

            directory = SMBDirectory.from_uncpath(directory_unc)
            listed, error = await directory.list(connection)
            _assert_success(listed, error, "directory list")
            assert file_name in directory.files

            await _delete_file(connection, file_unc)
        finally:
            deleted, error = await SMBDirectory.delete_unc(
                connection, directory_unc
            )
            _assert_success(deleted, error, "directory cleanup")


@pytest.mark.slow
@pytest.mark.capability("large_transfer")
async def test_large_transfer_preserves_size_and_digest(
    samba_destructive_profile
):
    profile = samba_destructive_profile
    profile.require_capability("large_transfer")
    file_name = _unique_name("large", ".bin")
    file_unc = profile.unc_path(file_name)
    size = (5 * 1024 * 1024) + 123
    pattern = bytes(bytearray(range(256)))
    payload = (pattern * ((size // len(pattern)) + 1))[:size]

    async with logged_in(profile) as connection:
        try:
            await _write_file(connection, file_unc, payload)
            downloaded = await _read_file(connection, file_unc)
            assert len(downloaded) == len(payload)
            assert hashlib.sha256(downloaded).digest() == hashlib.sha256(
                payload
            ).digest()
        finally:
            await _delete_file(connection, file_unc)


@pytest.mark.capability("security_descriptor")
async def test_file_security_descriptor_is_decoded(
    samba_destructive_profile
):
    profile = samba_destructive_profile
    profile.require_capability("security_descriptor")
    file_name = _unique_name("security", ".bin")
    file_unc = profile.unc_path(file_name)

    async with logged_in(profile) as connection:
        try:
            await _write_file(connection, file_unc, b"security descriptor")
            remote_file = SMBFile.from_uncpath(file_unc)
            descriptor, error = await remote_file.get_security_descriptor(
                connection
            )
            _assert_success(descriptor, error, "security descriptor query")
            assert descriptor.Owner is not None
            assert descriptor.Group is not None
            assert descriptor.Dacl is not None
        finally:
            await _delete_file(connection, file_unc)


@pytest.mark.capability("concurrency")
async def test_concurrent_sessions_round_trip_independent_files(
    samba_destructive_profile
):
    profile = samba_destructive_profile
    profile.require_capability("concurrency")

    async def worker(index):
        file_name = _unique_name("concurrent-{}".format(index), ".bin")
        file_unc = profile.unc_path(file_name)
        payload = (
            "session-{}:".format(index).encode("ascii") * (4096 + index)
        )
        async with logged_in(profile) as connection:
            try:
                await _write_file(connection, file_unc, payload)
                assert await _read_file(connection, file_unc) == payload
                return len(payload)
            finally:
                await _delete_file(connection, file_unc)

    sizes = await asyncio.gather(*(worker(index) for index in range(4)))
    assert len(sizes) == 4
    assert len(set(sizes)) == 4
