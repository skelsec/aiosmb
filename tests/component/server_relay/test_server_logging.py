import logging
from pathlib import Path

import pytest

from aiosmb.protocol.smb2.command_codes import SMB2Command
from aiosmb.protocol.smb2.commands import (
    CreateDisposition,
    CreateOptions,
    QUERY_DIRECTORY_REQ,
    QueryDirectoryFlag,
)
from aiosmb.protocol.smb2.message import SMB2Message
from aiosmb.server.serverconnection import TRACE_LEVEL
from aiosmb.wintypes.fscc.structures.fileinfoclass import FileInfoClass
from tests.component.server_relay.test_smb202_fileserver_crud import (
    create_request,
    send,
)
from tests.component.server_relay.test_smb202_server import (
    connect_tree,
    make_connection,
)


pytestmark = [pytest.mark.component, pytest.mark.asyncio]


async def test_info_logging_is_semantic_and_packet_dumps_require_trace(
    tmp_path: Path,
) -> None:
    logs = []

    async def collect(message: str) -> None:
        logs.append(message)

    connection, transport, _ = make_connection(
        {"Data": tmp_path},
        log_callback=collect,
        log_level=logging.INFO,
    )

    await connection.print("[PACKET] RAW_STRUCTURE")
    tree_id = await connect_tree(connection, transport, r"\\server\Data")

    created = await send(
        connection,
        transport,
        create_request("report.txt", CreateDisposition.FILE_OPEN_IF),
        SMB2Command.CREATE,
        tree_id,
        40,
    )
    assert isinstance(created, SMB2Message)

    opened_directory = await send(
        connection,
        transport,
        create_request(
            "",
            CreateDisposition.FILE_OPEN,
            CreateOptions.FILE_DIRECTORY_FILE,
        ),
        SMB2Command.CREATE,
        tree_id,
        41,
    )
    query = QUERY_DIRECTORY_REQ()
    query.FileInformationClass = FileInfoClass.FileBothDirectoryInformation
    query.Flags = QueryDirectoryFlag.SMB2_RESTART_SCANS
    query.FileIndex = 0
    query.FileId = opened_directory.command.FileId
    query.FileName = "*"
    query.OutputBufferLength = 4096
    await send(
        connection,
        transport,
        query,
        SMB2Command.QUERY_DIRECTORY,
        tree_id,
        42,
    )

    assert not any("RAW_STRUCTURE" in entry for entry in logs)
    assert any("connect share='Data' type=disk" in entry for entry in logs)
    assert any(
        "create file share=Data path='report.txt'" in entry
        for entry in logs
    )
    assert any(
        "list directory share=Data" in entry and "pattern='*'" in entry
        for entry in logs
    )

    connection.settings.log_level = TRACE_LEVEL
    await connection.print("[PACKET] RAW_STRUCTURE")

    assert any("RAW_STRUCTURE" in entry for entry in logs)
    assert any("[TRACE]" in entry for entry in logs)
