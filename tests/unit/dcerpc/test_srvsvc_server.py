"""Round-trip tests for the minimal read-only SRVSVC server."""

import pytest

from aiosmb.dcerpc.v5 import srvs, system_errors
from aiosmb.dcerpc.v5.ndr import NULL
from aiosmb.dcerpc.v5.rpcrt import (
    CtxItem,
    DCERPC,
    MSRPC_BIND,
    MSRPC_REQUEST,
    MSRPCBind,
    MSRPCHeader,
    MSRPCRequestHeader,
    MSRPCRespHeader,
)
from aiosmb.dcerpc.v5.servers.srvsvc import (
    NERR_NET_NAME_NOT_FOUND,
    SRVSVCServer,
    SRVSVCShare,
)


pytestmark = [pytest.mark.unit, pytest.mark.asyncio]


def _bind_pdu():
    bind = MSRPCBind()
    item = CtxItem()
    item["ContextID"] = 0
    item["TransItems"] = 1
    item["AbstractSyntax"] = srvs.MSRPC_UUID_SRVS
    item["TransferSyntax"] = DCERPC.NDRSyntax
    bind.addCtxItem(item)
    header = MSRPCHeader()
    header["type"] = MSRPC_BIND
    header["call_id"] = 1
    header["pduData"] = bind.getData()
    return header.get_packet()


def _request_pdu(request, call_id=2):
    header = MSRPCRequestHeader()
    header["type"] = MSRPC_REQUEST
    header["call_id"] = call_id
    header["ctx_id"] = 0
    header["op_num"] = request.opnum
    header["pduData"] = request.getData()
    header["alloc_hint"] = len(header["pduData"])
    return header.get_packet()


async def _round_trip(server, request, response_type, call_id=2):
    if not server.runtime.bound:
        bind_replies = await server.feed_data(_bind_pdu())
        assert len(bind_replies) == 1
    replies = await server.feed_data(_request_pdu(request, call_id))
    stub = b"".join(MSRPCRespHeader(item)["pduData"] for item in replies)
    return response_type(stub)


def _share_enum_request(level):
    request = srvs.NetrShareEnum()
    request["ServerName"] = "\x00"
    request["InfoStruct"]["Level"] = level
    request["InfoStruct"]["ShareInfo"]["tag"] = level
    request["InfoStruct"]["ShareInfo"]["Level%d" % level][
        "Buffer"
    ] = NULL
    request["PreferedMaximumLength"] = 0xFFFFFFFF
    request["ResumeHandle"] = 0
    return request


def _share_get_request(name, level):
    request = srvs.NetrShareGetInfo()
    request["ServerName"] = NULL
    request["NetName"] = name + "\x00"
    request["Level"] = level
    return request


def _server_get_request(level):
    request = srvs.NetrServerGetInfo()
    request["ServerName"] = NULL
    request["Level"] = level
    return request


@pytest.mark.parametrize(
    "level,name_field",
    [
        (0, "shi0_netname"),
        (1, "shi1_netname"),
        (2, "shi2_netname"),
    ],
)
async def test_share_enum_levels_round_trip_existing_ndr_types(
    level, name_field
):
    async def provider():
        return {
            "Data": {
                "path": "/srv/data",
                "remark": "Files",
            }
        }

    server = SRVSVCServer(share_provider=provider)
    response = await _round_trip(
        server,
        _share_enum_request(level),
        srvs.NetrShareEnumResponse,
    )

    entries = response["InfoStruct"]["ShareInfo"][
        "Level%d" % level
    ]["Buffer"]
    names = [entry[name_field].rstrip("\x00") for entry in entries]
    assert names == ["Data", "IPC$"]
    assert response["TotalEntries"] == 2
    assert response["ErrorCode"] == system_errors.ERROR_SUCCESS
    if level in (1, 2):
        ipc = entries[1]
        assert ipc["shi%d_type" % level] == (
            srvs.STYPE_IPC | srvs.STYPE_SPECIAL
        )


@pytest.mark.parametrize("level", [0, 1, 2])
async def test_share_get_info_levels_include_provider_metadata(level):
    share = SRVSVCShare(
        name="Data",
        path="/srv/data",
        remark="Read only files",
        permissions=7,
        max_uses=20,
        current_uses=2,
    )
    server = SRVSVCServer(share_provider=lambda: [share])

    response = await _round_trip(
        server,
        _share_get_request("data", level),
        srvs.NetrShareGetInfoResponse,
    )

    info = response["InfoStruct"]["ShareInfo%d" % level]
    assert info["shi%d_netname" % level].rstrip("\x00") == "Data"
    assert response["ErrorCode"] == system_errors.ERROR_SUCCESS
    if level == 2:
        assert info["shi2_path"].rstrip("\x00") == "/srv/data"
        assert info["shi2_permissions"] == 7
        assert info["shi2_max_uses"] == 20
        assert info["shi2_current_uses"] == 2


@pytest.mark.parametrize("level", [100, 101])
async def test_server_get_info_levels_round_trip(level):
    server = SRVSVCServer(
        server_name="FILE01",
        server_comment="Test server",
        version_major=6,
        version_minor=3,
    )

    response = await _round_trip(
        server,
        _server_get_request(level),
        srvs.NetrServerGetInfoResponse,
    )

    info = response["InfoStruct"]["ServerInfo%d" % level]
    assert info["sv%d_name" % level].rstrip("\x00") == "FILE01"
    assert info["sv%d_platform_id" % level] == srvs.PLATFORM_ID_NT
    assert response["ErrorCode"] == system_errors.ERROR_SUCCESS
    if level == 101:
        assert info["sv101_version_major"] == 6
        assert info["sv101_version_minor"] == 3
        assert info["sv101_comment"].rstrip("\x00") == "Test server"


async def test_missing_share_and_unsupported_levels_are_clean_errors():
    server = SRVSVCServer(share_provider=lambda: {})

    missing = await _round_trip(
        server,
        _share_get_request("missing", 1),
        srvs.NetrShareGetInfoResponse,
        call_id=2,
    )
    unsupported = await _round_trip(
        server,
        _share_get_request("IPC$", 502),
        srvs.NetrShareGetInfoResponse,
        call_id=3,
    )
    unsupported_server = await _round_trip(
        server,
        _server_get_request(102),
        srvs.NetrServerGetInfoResponse,
        call_id=4,
    )

    assert missing["ErrorCode"] == NERR_NET_NAME_NOT_FOUND
    assert unsupported["ErrorCode"] == system_errors.ERROR_INVALID_LEVEL
    assert unsupported_server["ErrorCode"] == (
        system_errors.ERROR_INVALID_LEVEL
    )
