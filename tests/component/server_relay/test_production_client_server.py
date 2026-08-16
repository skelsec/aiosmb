from __future__ import annotations

import asyncio
import socket
from pathlib import Path

import pytest
from asysocks.unicomm.common.target import UniProto, UniTarget

from aiosmb.commons.connection.factory import SMBConnectionFactory
from aiosmb.commons.interfaces.directory import SMBDirectory
from aiosmb.commons.interfaces.file import SMBFile
from aiosmb.commons.interfaces.machine import SMBMachine
from aiosmb.server.server import SMBServer, SMBServerSettings


pytestmark = [pytest.mark.component, pytest.mark.asyncio]


def free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def client_connection(port: int):
    return SMBConnectionFactory.from_url(
        "smb202+ntlm-password://LAB\\alice:secret@127.0.0.1:{}".format(
            port
        )
    ).get_connection()


def anonymous_client_connection(port: int):
    return SMBConnectionFactory.from_url(
        "smb202+ntlm-none://127.0.0.1:{}/Data".format(port)
    ).get_connection()


@pytest.mark.parametrize(
    "require_signing,disable_ess",
    [
        (False, False),
        (True, False),
        (False, True),
    ],
)
async def test_production_client_crud_and_srvsvc(
    tmp_path: Path, require_signing: bool, disable_ess: bool
) -> None:
    port = free_port()
    logs = []

    async def collect_log(message: str) -> None:
        logs.append(message)

    settings = SMBServerSettings.from_password(
        "alice",
        "secret",
        "LAB",
        log_callback=collect_log,
        disable_ess=disable_ess,
    )
    settings.RequireSigning = require_signing
    settings.shares = {"Data": tmp_path}
    server = SMBServer(
        UniTarget("127.0.0.1", port, UniProto.SERVER_TCP), settings
    )
    server_task, error = await server.run()
    assert error is None
    await asyncio.sleep(0.05)

    connection = client_connection(port)
    try:
        logged_in, error = await connection.login()
        assert logged_in is True
        assert error is None
        assert any(
            "NetNTLMv2 hash=alice::LAB:" in message
            for message in logs
        )

        names = []
        async for share, error in SMBMachine(connection).list_shares():
            assert error is None
            names.append(share.name)
        assert {name.upper() for name in names} == {"DATA", "IPC$"}

        remote = SMBFile.from_remotepath(
            connection, r"\Data\production.bin"
        )
        opened, error = await remote.open(connection, "w")
        assert opened is True and error is None
        count, error = await remote.write(b"production-client")
        assert count == len(b"production-client") and error is None
        await remote.close()

        fetched = SMBFile.from_remotepath(
            connection, r"\Data\production.bin"
        )
        opened, error = await fetched.open(connection, "r")
        assert opened is True and error is None
        data, error = await fetched.read()
        assert data == b"production-client" and error is None
        await fetched.close()

        root = SMBDirectory.from_remotepath(connection, r"\Data")
        listed = []
        async for entry, entry_type, error in root.list_gen(connection):
            assert error is None
            listed.append((entry.name, entry_type))
        assert ("production.bin", "file") in listed

        made, error = await SMBDirectory.create_remote(
            connection, r"\Data\created"
        )
        assert made is True and error is None
        assert (tmp_path / "created").is_dir()

        deleted, error = await fetched.delete()
        assert deleted is True and error is None
        assert not (tmp_path / "production.bin").exists()
    finally:
        await connection.terminate()

    reconnect = client_connection(port)
    try:
        logged_in, error = await reconnect.login()
        assert logged_in is True and error is None
    finally:
        await reconnect.terminate()
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass


async def test_production_client_anonymous_crud_and_srvsvc(
    tmp_path: Path,
) -> None:
    port = free_port()
    settings = SMBServerSettings.from_anonymous(log_callback=None)
    settings.shares = {"Data": tmp_path}
    server = SMBServer(
        UniTarget("127.0.0.1", port, UniProto.SERVER_TCP), settings
    )
    server_task, error = await server.run()
    assert error is None
    await asyncio.sleep(0.05)

    connection = anonymous_client_connection(port)
    try:
        logged_in, error = await connection.login()
        assert logged_in is True
        assert error is None
        assert connection.is_anonymous is True
        assert connection.is_guest is False
        assert connection.SessionKey is None
        assert connection.signing_required is False

        names = []
        async for share, error in SMBMachine(connection).list_shares():
            assert error is None
            names.append(share.name)
        assert {name.upper() for name in names} == {"DATA", "IPC$"}

        remote = SMBFile.from_remotepath(
            connection, r"\Data\anonymous.bin"
        )
        opened, error = await remote.open(connection, "w")
        assert opened is True and error is None
        count, error = await remote.write(b"anonymous-create")
        assert count == len(b"anonymous-create") and error is None
        await remote.close()

        updated = SMBFile.from_remotepath(
            connection, r"\Data\anonymous.bin"
        )
        opened, error = await updated.open(connection, "w")
        assert opened is True and error is None
        count, error = await updated.write(b"anonymous-update")
        assert count == len(b"anonymous-update") and error is None
        await updated.close()

        fetched = SMBFile.from_remotepath(
            connection, r"\Data\anonymous.bin"
        )
        opened, error = await fetched.open(connection, "r")
        assert opened is True and error is None
        data, error = await fetched.read()
        assert data == b"anonymous-update" and error is None
        await fetched.close()

        deleted, error = await fetched.delete()
        assert deleted is True and error is None
        assert not (tmp_path / "anonymous.bin").exists()
    finally:
        await connection.terminate()
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass


async def test_anonymous_client_reports_required_signing_conflict(
    tmp_path: Path,
) -> None:
    port = free_port()
    settings = SMBServerSettings.from_anonymous(log_callback=None)
    settings.RequireSigning = True
    settings.shares = {"Data": tmp_path}
    server = SMBServer(
        UniTarget("127.0.0.1", port, UniProto.SERVER_TCP), settings
    )
    server_task, error = await server.run()
    assert error is None
    await asyncio.sleep(0.05)

    connection = anonymous_client_connection(port)
    try:
        logged_in, error = await connection.login()
        assert logged_in is False
        assert error is not None
        assert "server requires signing" in str(error)
    finally:
        await connection.terminate()
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass
