from __future__ import annotations

from pathlib import Path

import pytest

from aiosmb.dcerpc.v5 import srvs
from aiosmb.dcerpc.v5.rpcrt import MSRPCBindAck, MSRPCRespHeader
from aiosmb.protocol.smb2.command_codes import SMB2Command
from aiosmb.protocol.smb2.commands import (
    CreateDisposition,
    READ_REQ,
    WRITE_REQ,
)
from aiosmb.wintypes.ntstatus import NTStatus
from tests.component.server_relay.test_smb202_fileserver_crud import (
    create_request,
    send,
)
from tests.component.server_relay.test_smb202_server import (
    connect_tree,
    make_connection,
)
from tests.unit.dcerpc.test_srvsvc_server import (
    _bind_pdu,
    _request_pdu,
    _share_enum_request,
)


pytestmark = [pytest.mark.component, pytest.mark.asyncio]


async def pipe_write(connection, transport, tree_id, file_id, data, message_id):
    request = WRITE_REQ()
    request.Offset = 0
    request.FileId = file_id
    request.Data = data
    response = await send(
        connection,
        transport,
        request,
        SMB2Command.WRITE,
        tree_id,
        message_id,
    )
    assert response.header.Status == NTStatus.SUCCESS
    assert response.command.Count == len(data)


async def pipe_read(connection, transport, tree_id, file_id, message_id):
    request = READ_REQ()
    request.Length = 65536
    request.Offset = 0
    request.FileId = file_id
    request.MinimumCount = 0
    response = await send(
        connection,
        transport,
        request,
        SMB2Command.READ,
        tree_id,
        message_id,
    )
    assert response.header.Status == NTStatus.SUCCESS
    return response.command.Buffer


async def test_srvsvc_share_enum_over_ipc_named_pipe(tmp_path: Path) -> None:
    connection, transport, _ = make_connection({"Data": tmp_path})
    tree_id = await connect_tree(connection, transport, r"\\server\IPC$")
    opened = await send(
        connection,
        transport,
        create_request("srvsvc", CreateDisposition.FILE_OPEN),
        SMB2Command.CREATE,
        tree_id,
        40,
    )
    file_id = opened.command.FileId

    await pipe_write(connection, transport, tree_id, file_id, _bind_pdu(), 41)
    bind_ack = MSRPCBindAck(
        await pipe_read(connection, transport, tree_id, file_id, 42)
    )
    assert bind_ack.getCtxItem(1)["Result"] == 0

    request = _share_enum_request(1)
    await pipe_write(
        connection,
        transport,
        tree_id,
        file_id,
        _request_pdu(request),
        43,
    )
    response_pdu = MSRPCRespHeader(
        await pipe_read(connection, transport, tree_id, file_id, 44)
    )
    response = srvs.NetrShareEnumResponse(response_pdu["pduData"])
    entries = response["InfoStruct"]["ShareInfo"]["Level1"]["Buffer"]
    names = [entry["shi1_netname"].rstrip("\x00") for entry in entries]
    assert names == ["Data", "IPC$"]
