from __future__ import annotations

import asyncio
import os
import shutil
import socket
from pathlib import Path

import pytest
from asysocks.unicomm.common.target import UniProto, UniTarget

from aiosmb.server.server import SMBServer, SMBServerSettings


pytestmark = [
    pytest.mark.component,
    pytest.mark.samba,
    pytest.mark.asyncio,
]


def free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


@pytest.mark.skipif(
    os.environ.get("AIOSMB_RUN_LOCAL_SMBCLIENT") != "1"
    or shutil.which("smbclient") is None,
    reason=(
        "set AIOSMB_RUN_LOCAL_SMBCLIENT=1 and install Samba smbclient "
        "to run local server interoperability"
    ),
)
@pytest.mark.parametrize("disable_ess", [False, True])
async def test_samba_smbclient_crud_against_local_server(
    tmp_path: Path, disable_ess: bool
) -> None:
    share_root = tmp_path / "share"
    share_root.mkdir()
    upload = tmp_path / "upload.txt"
    download = tmp_path / "download.txt"
    upload.write_bytes(b"samba-client")
    port = free_port()

    settings = SMBServerSettings.from_password(
        "alice",
        "secret",
        "LAB",
        log_callback=None,
        disable_ess=disable_ess,
    )
    settings.shares = {"Data": share_root}
    server = SMBServer(
        UniTarget("127.0.0.1", port, UniProto.SERVER_TCP), settings
    )
    server_task, error = await server.run()
    assert error is None
    await asyncio.sleep(0.05)

    commands = (
        "ls; put {upload} remote.txt; get remote.txt {download}; "
        "rename remote.txt renamed.txt; mkdir folder; del renamed.txt; "
        "rmdir folder; ls"
    ).format(upload=upload, download=download)
    process = await asyncio.create_subprocess_exec(
        "smbclient",
        "//127.0.0.1/Data",
        "-p",
        str(port),
        "-U",
        "LAB/alice%secret",
        "-m",
        "SMB2",
        "-c",
        commands,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    try:
        output, _ = await asyncio.wait_for(process.communicate(), 15)
        assert process.returncode == 0, output.decode(errors="replace")
        assert download.read_bytes() == upload.read_bytes()
        assert list(share_root.iterdir()) == []
    finally:
        if process.returncode is None:
            process.kill()
            await process.wait()
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass


@pytest.mark.skipif(
    os.environ.get("AIOSMB_RUN_LOCAL_SMBCLIENT") != "1"
    or shutil.which("smbclient") is None,
    reason=(
        "set AIOSMB_RUN_LOCAL_SMBCLIENT=1 and install Samba smbclient "
        "to run local server interoperability"
    ),
)
async def test_samba_smbclient_anonymous_crud_against_local_server(
    tmp_path: Path,
) -> None:
    share_root = tmp_path / "anonymous-share"
    share_root.mkdir()
    upload = tmp_path / "anonymous-upload.txt"
    download = tmp_path / "anonymous-download.txt"
    upload.write_bytes(b"anonymous-samba-client")
    port = free_port()

    settings = SMBServerSettings.from_anonymous(log_callback=None)
    settings.shares = {"Public": share_root}
    server = SMBServer(
        UniTarget("127.0.0.1", port, UniProto.SERVER_TCP), settings
    )
    server_task, error = await server.run()
    assert error is None
    await asyncio.sleep(0.05)

    process = await asyncio.create_subprocess_exec(
        "smbclient",
        "//127.0.0.1/Public",
        "-p",
        str(port),
        "-N",
        "-U",
        "%",
        "-m",
        "SMB2",
        "-c",
        "put {upload} anonymous.txt; get anonymous.txt {download}; "
        "del anonymous.txt".format(upload=upload, download=download),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    try:
        output, _ = await asyncio.wait_for(process.communicate(), 15)
        assert process.returncode == 0, output.decode(errors="replace")
        assert download.read_bytes() == upload.read_bytes()
        assert list(share_root.iterdir()) == []
    finally:
        if process.returncode is None:
            process.kill()
            await process.wait()
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass
