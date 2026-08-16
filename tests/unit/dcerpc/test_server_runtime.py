"""Offline tests for the connection-oriented DCE/RPC server runtime."""

import struct

import pytest

from aiosmb.dcerpc.v5.rpcrt import (
    CtxItem,
    DCERPC,
    MSRPC_ALTERCTX,
    MSRPC_ALTERCTX_R,
    MSRPC_BIND,
    MSRPC_BINDACK,
    MSRPC_FAULT,
    MSRPC_REQUEST,
    MSRPC_RESPONSE,
    MSRPCBind,
    MSRPCBindAck,
    MSRPCHeader,
    MSRPCRequestHeader,
    MSRPCRespHeader,
    PFC_FIRST_FRAG,
    PFC_LAST_FRAG,
)
from aiosmb.dcerpc.v5.servers.runtime import (
    DCERPCServerRuntime,
    NCA_S_OP_RNG_ERROR,
    NCA_S_UNSUPPORTED_AUTHN_LEVEL,
)
from aiosmb.dcerpc.v5.uuid import uuidtup_to_bin


pytestmark = [pytest.mark.unit, pytest.mark.asyncio]

TEST_INTERFACE = uuidtup_to_bin(
    ("12345678-1234-5678-9abc-def012345678", "1.0")
)
SECOND_INTERFACE = uuidtup_to_bin(
    ("87654321-4321-8765-cba9-876543210fed", "2.0")
)


def _bind_pdu(
    interface=TEST_INTERFACE,
    transfer_syntax=DCERPC.NDRSyntax,
    call_id=7,
    context_id=3,
    packet_type=MSRPC_BIND,
    max_xmit=4280,
    max_recv=4280,
):
    bind = MSRPCBind()
    bind["max_tfrag"] = max_xmit
    bind["max_rfrag"] = max_recv
    item = CtxItem()
    item["ContextID"] = context_id
    item["TransItems"] = 1
    item["AbstractSyntax"] = interface
    item["TransferSyntax"] = transfer_syntax
    bind.addCtxItem(item)

    header = MSRPCHeader()
    header["type"] = packet_type
    header["call_id"] = call_id
    header["pduData"] = bind.getData()
    return header.get_packet()


def _request_pdu(
    stub,
    call_id=11,
    context_id=3,
    opnum=4,
    flags=PFC_FIRST_FRAG | PFC_LAST_FRAG,
    alloc_hint=None,
):
    header = MSRPCRequestHeader()
    header["type"] = MSRPC_REQUEST
    header["flags"] = flags
    header["call_id"] = call_id
    header["ctx_id"] = context_id
    header["op_num"] = opnum
    header["alloc_hint"] = len(stub) if alloc_hint is None else alloc_hint
    header["pduData"] = stub
    return header.get_packet()


async def _bind(runtime):
    replies = await runtime.feed_data(_bind_pdu())
    assert len(replies) == 1
    return MSRPCBindAck(replies[0])


async def test_bind_ack_matches_golden_ndr32_wire_image():
    runtime = DCERPCServerRuntime()
    runtime.register_interface(TEST_INTERFACE, {4: lambda stub: stub})

    bind = _bind_pdu()
    replies = []
    for octet in bind:
        replies.extend(await runtime.feed_data(bytes([octet])))

    assert len(replies) == 1
    assert replies[0].hex() == (
        "05000c03100000003800000007000000"
        "b810b810010000000000000001000000"
        "00000000045d888aeb1cc9119fe80800"
        "2b10486002000000"
    )
    ack = MSRPCBindAck(replies[0])
    assert ack["type"] == MSRPC_BINDACK
    assert ack["call_id"] == 7
    assert ack.getCtxItem(1)["Result"] == 0
    assert runtime.contexts[3].abstract_syntax == TEST_INTERFACE


async def test_ndr64_only_bind_is_rejected_without_binding_context():
    runtime = DCERPCServerRuntime()
    runtime.register_interface(TEST_INTERFACE, {4: lambda stub: stub})

    replies = await runtime.feed_data(
        _bind_pdu(transfer_syntax=DCERPC.NDR64Syntax)
    )

    ack = MSRPCBindAck(replies[0])
    result = ack.getCtxItem(1)
    assert result["Result"] == 2
    assert result["Reason"] == 2
    assert 3 not in runtime.contexts


async def test_alter_context_adds_another_registered_interface():
    runtime = DCERPCServerRuntime()
    runtime.register_interface(TEST_INTERFACE, {4: lambda stub: stub})
    runtime.register_interface(SECOND_INTERFACE, {9: lambda stub: stub})
    await _bind(runtime)

    replies = await runtime.feed_data(
        _bind_pdu(
            interface=SECOND_INTERFACE,
            call_id=8,
            context_id=5,
            packet_type=MSRPC_ALTERCTX,
        )
    )

    ack = MSRPCBindAck(replies[0])
    assert ack["type"] == MSRPC_ALTERCTX_R
    assert ack.getCtxItem(1)["Result"] == 0
    assert runtime.contexts[3].abstract_syntax == TEST_INTERFACE
    assert runtime.contexts[5].abstract_syntax == SECOND_INTERFACE


async def test_fragmented_request_is_reassembled_and_response_is_fragmented():
    runtime = DCERPCServerRuntime(max_xmit_frag=32)
    runtime.register_interface(
        TEST_INTERFACE, {4: lambda stub: stub.upper() * 3}
    )
    await _bind(runtime)

    first = _request_pdu(
        b"abc",
        call_id=41,
        flags=PFC_FIRST_FRAG,
        alloc_hint=6,
    )
    last = _request_pdu(
        b"def",
        call_id=41,
        flags=PFC_LAST_FRAG,
        alloc_hint=6,
    )

    assert await runtime.feed_data(first) == []
    replies = await runtime.feed_data(last)

    assert len(replies) == 3
    parsed = [MSRPCRespHeader(reply) for reply in replies]
    assert [item["type"] for item in parsed] == [MSRPC_RESPONSE] * 3
    assert [item["call_id"] for item in parsed] == [41] * 3
    assert [item["ctx_id"] for item in parsed] == [3] * 3
    assert [item["flags"] for item in parsed] == [
        PFC_FIRST_FRAG,
        0,
        PFC_LAST_FRAG,
    ]
    assert [item["alloc_hint"] for item in parsed] == [18, 10, 2]
    assert b"".join(item["pduData"] for item in parsed) == (
        b"ABCDEFABCDEFABCDEF"
    )
    assert all(len(reply) <= 32 for reply in replies)


async def test_unregistered_opnum_returns_standard_fault():
    runtime = DCERPCServerRuntime()
    runtime.register_interface(TEST_INTERFACE, {4: lambda stub: stub})
    await _bind(runtime)

    replies = await runtime.feed_data(_request_pdu(b"", opnum=99))

    fault = MSRPCRespHeader(replies[0])
    assert fault["type"] == MSRPC_FAULT
    assert fault["call_id"] == 11
    assert struct.unpack("<I", fault["pduData"][:4])[0] == (
        NCA_S_OP_RNG_ERROR
    )


async def test_authenticated_request_is_rejected_with_clean_fault():
    runtime = DCERPCServerRuntime()
    runtime.register_interface(TEST_INTERFACE, {4: lambda stub: stub})
    await _bind(runtime)
    request = bytearray(_request_pdu(b"stub"))
    request.extend(struct.pack("<BBBBI", 10, 2, 0, 0, 1))
    request.extend(b"x")
    struct.pack_into("<H", request, 8, len(request))
    struct.pack_into("<H", request, 10, 1)

    replies = await runtime.feed_data(bytes(request))

    fault = MSRPCRespHeader(replies[0])
    assert fault["type"] == MSRPC_FAULT
    assert struct.unpack("<I", fault["pduData"][:4])[0] == (
        NCA_S_UNSUPPORTED_AUTHN_LEVEL
    )


async def test_negotiated_fragment_sizes_follow_peer_limits():
    runtime = DCERPCServerRuntime(
        max_xmit_frag=4096,
        max_recv_frag=8192,
    )
    runtime.register_interface(TEST_INTERFACE, {4: lambda stub: stub})

    replies = await runtime.feed_data(
        _bind_pdu(max_xmit=2048, max_recv=1024)
    )

    ack = MSRPCBindAck(replies[0])
    assert runtime.max_xmit_frag == 1024
    assert runtime.max_recv_frag == 2048
    assert ack["max_tfrag"] == 1024
    assert ack["max_rfrag"] == 2048
