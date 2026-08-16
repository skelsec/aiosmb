"""Tests for the per-pipe SMB DCE/RPC byte-stream adapter."""

import asyncio

import pytest

from aiosmb.dcerpc.v5.servers.transport.smbtransport import (
    DCERPCServerSMBTransport,
)


pytestmark = [pytest.mark.unit, pytest.mark.asyncio]


async def test_reads_span_queue_records_and_preserve_the_tail():
    transport = DCERPCServerSMBTransport()
    await transport.feed_data(b"ab")
    await transport.feed_data(b"cdef")
    await transport.feed_eof()

    assert await transport.readexactly(4) == b"abcd"
    assert await transport.read() == b"ef"
    assert await transport.read() is None


async def test_writes_use_deterministic_pipe_record_boundaries():
    output = asyncio.Queue()
    transport = DCERPCServerSMBTransport(
        smb_out_q=output,
        max_write_size=3,
    )

    assert await transport.write(b"abcdefgh") == 8

    assert await output.get() == b"abc"
    assert await output.get() == b"def"
    assert await output.get() == b"gh"


async def test_pipe_instances_do_not_share_stream_state():
    first = DCERPCServerSMBTransport(pipe_name="srvsvc")
    second = DCERPCServerSMBTransport(pipe_name="srvsvc")
    await first.feed_data(b"first")
    await second.feed_data(b"second")

    assert await first.read() == b"first"
    assert await second.read() == b"second"


async def test_disconnect_unblocks_a_pending_reader_with_eof():
    transport = DCERPCServerSMBTransport()
    reader = asyncio.create_task(transport.read())
    await transport.disconnect()

    assert await reader is None
