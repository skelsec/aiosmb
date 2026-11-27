"""SMB2/SMB3 header, envelope, dispatch, and compound vectors."""

import io
import struct

import pytest

from aiosmb.protocol.smb2.command_codes import SMB2Command
from aiosmb.protocol.smb2.commands.echo import ECHO_REPLY, ECHO_REQ
from aiosmb.protocol.smb2.commands.error import ERROR_REPLY
from aiosmb.protocol.smb2.commands.logoff import LOGOFF_REQ
from aiosmb.protocol.smb2.commands.negotiate import (
    SMB2Cipher,
    SMB2CompressionFlags,
    SMB2CompressionType,
)
from aiosmb.protocol.smb2.headers.asynch import SMB2Header_ASYNC
from aiosmb.protocol.smb2.headers.common import SMB2HeaderFlag
from aiosmb.protocol.smb2.headers.compression import (
    SMB2Header_COMPRESSION_TRANSFORM,
)
from aiosmb.protocol.smb2.headers.sync import SMB2Header_SYNC
from aiosmb.protocol.smb2.headers.transform import SMB2Header_TRANSFORM
from aiosmb.protocol.smb2.message import (
    SMB2Compression,
    SMB2Message,
    SMB2Transform,
)
from aiosmb.wintypes.ntstatus import NTStatus


pytestmark = pytest.mark.unit


def _sync_header(
    command,
    flags=SMB2HeaderFlag(0),
    status=NTStatus.SUCCESS,
    next_command=0,
    message_id=0x0102030405060708,
):
    return struct.pack(
        "<4sHHIHHIIQIIQ16s",
        b"\xfeSMB",
        64,
        3,
        status.value,
        command.value,
        5,
        int(flags),
        next_command,
        message_id,
        0,
        0x11223344,
        0x8877665544332211,
        bytes(range(16)),
    )


def _async_header(command, status=NTStatus.SUCCESS):
    flags = (
        SMB2HeaderFlag.SMB2_FLAGS_SERVER_TO_REDIR
        | SMB2HeaderFlag.SMB2_FLAGS_ASYNC_COMMAND
    )
    return struct.pack(
        "<4sHHIHHIIQ8s8s16s",
        b"\xfeSMB",
        64,
        2,
        status.value,
        command.value,
        7,
        int(flags),
        0,
        0xAABBCCDDEEFF0011,
        bytes.fromhex("0807060504030201"),
        bytes.fromhex("1122334455667788"),
        b"\xaa" * 16,
    )


def test_sync_header_matches_golden_and_round_trips():
    golden = _sync_header(
        SMB2Command.ECHO,
        SMB2HeaderFlag.SMB2_FLAGS_SIGNED,
    )
    header = SMB2Header_SYNC.from_buffer(io.BytesIO(golden))

    assert len(golden) == 64
    assert header.StructureSize == 64
    assert header.CreditCharge == 3
    assert header.Command is SMB2Command.ECHO
    assert header.Flags == SMB2HeaderFlag.SMB2_FLAGS_SIGNED
    assert header.MessageId == 0x0102030405060708
    assert header.TreeId == 0x11223344
    assert header.SessionId == 0x8877665544332211
    assert header.Signature == bytes(range(16))
    assert header.to_bytes() == golden


def test_async_header_matches_golden_and_dispatches_reply():
    golden = _async_header(SMB2Command.ECHO)
    parsed_header = SMB2Header_ASYNC.from_buffer(io.BytesIO(golden))
    message = SMB2Message.from_bytes(golden + b"\x04\x00\x00\x00")

    assert parsed_header.to_bytes() == golden
    assert parsed_header.AsyncId == bytes.fromhex("0807060504030201")
    assert parsed_header.SessionId == bytes.fromhex("1122334455667788")
    assert isinstance(message.header, SMB2Header_ASYNC)
    assert isinstance(message.command, ECHO_REPLY)
    assert message.to_bytes() == golden + b"\x04\x00\x00\x00"


@pytest.mark.parametrize(
    "flags, expected_type",
    [
        (SMB2HeaderFlag(0), ECHO_REQ),
        (SMB2HeaderFlag.SMB2_FLAGS_SERVER_TO_REDIR, ECHO_REPLY),
    ],
    ids=["request", "reply"],
)
def test_message_dispatch_uses_direction_flag(flags, expected_type):
    wire = _sync_header(SMB2Command.ECHO, flags) + b"\x04\x00\x00\x00"

    message = SMB2Message.from_bytes(wire)

    assert isinstance(message.command, expected_type)
    assert message.to_bytes() == wire


def test_non_success_response_dispatches_error_body():
    wire = (
        _sync_header(
            SMB2Command.CREATE,
            SMB2HeaderFlag.SMB2_FLAGS_SERVER_TO_REDIR,
            status=NTStatus.ACCESS_DENIED,
        )
        + struct.pack("<HBBI", 9, 0, 0, 0)
        + b"\xff"
    )

    message = SMB2Message.from_bytes(wire)

    assert isinstance(message.command, ERROR_REPLY)
    assert message.command.ByteCount == 0
    assert message.command.ErrorData is None
    assert message.to_bytes() == wire


def test_transform_header_and_envelope_golden_round_trip():
    golden_header = (
        b"\xfdSMB"
        + bytes(range(16))
        + bytes(range(16, 32))
        + struct.pack("<IHHQ", 4096, 0, SMB2Cipher.AES_128_GCM.value, 0x1234)
    )
    wire = golden_header + b"ciphertext"

    transform = SMB2Transform.from_bytes(wire)

    assert len(golden_header) == 52
    assert isinstance(transform.header, SMB2Header_TRANSFORM)
    assert transform.header.Signature == bytes(range(16))
    assert transform.header.Nonce == bytes(range(16, 32))
    assert transform.header.OriginalMessageSize == 4096
    assert transform.header.EncryptionAlgorithm is SMB2Cipher.AES_128_GCM
    assert transform.header.SessionId == 0x1234
    assert transform.data == b"ciphertext"
    assert transform.to_bytes() == wire


def test_compression_header_and_envelope_golden_round_trip():
    golden_header = (
        b"\xfcSMB"
        + struct.pack(
            "<IHHI",
            8192,
            SMB2CompressionType.LZNT1.value,
            SMB2CompressionFlags.CHAINED.value,
            128,
        )
    )
    wire = golden_header + b"compressed"

    compression = SMB2Compression.from_bytes(wire)

    assert len(golden_header) == 16
    assert isinstance(compression.header, SMB2Header_COMPRESSION_TRANSFORM)
    assert compression.header.OriginalCompressedSegmentSize == 8192
    assert compression.header.CompressionAlgorithm is SMB2CompressionType.LZNT1
    assert compression.header.Flags is SMB2CompressionFlags.CHAINED
    assert compression.header.Offset == 128
    assert compression.data == b"compressed"
    assert compression.to_bytes() == wire


def test_compression_envelope_rejects_truncated_fixed_header():
    with pytest.raises(ValueError, match="Truncated"):
        SMB2Compression.from_bytes(b"\xfcSMB" + b"\x00" * 11)


def test_unchained_compression_header_validates_bounds_and_negotiation():
    header = SMB2Header_COMPRESSION_TRANSFORM()
    header.OriginalCompressedSegmentSize = 10
    header.CompressionAlgorithm = SMB2CompressionType.LZ77
    header.Flags = SMB2CompressionFlags.NONE
    header.Offset = 4

    assert header.validate(
        payload_length=8,
        max_output_size=32,
        allowed_algorithms=(SMB2CompressionType.LZ77,),
    ) == 14

    header.Offset = 9
    with pytest.raises(ValueError, match="offset"):
        header.validate(
            payload_length=8,
            max_output_size=32,
            allowed_algorithms=(SMB2CompressionType.LZ77,),
        )

    header.Offset = 4
    with pytest.raises(ValueError, match="not negotiated"):
        header.validate(
            payload_length=8,
            max_output_size=32,
            allowed_algorithms=(SMB2CompressionType.LZNT1,),
        )

    header.Flags = SMB2CompressionFlags.CHAINED
    with pytest.raises(ValueError, match="Chained"):
        header.validate(
            payload_length=8,
            max_output_size=32,
            allowed_algorithms=(SMB2CompressionType.LZ77,),
        )


def test_compound_next_command_is_aligned_and_each_slice_dispatches():
    first_length = 72
    first = (
        _sync_header(
            SMB2Command.ECHO,
            next_command=first_length,
            message_id=1,
        )
        + b"\x04\x00\x00\x00"
        + b"\x00" * 4
    )
    second = (
        _sync_header(SMB2Command.LOGOFF, message_id=2)
        + b"\x04\x00\x00\x00"
    )
    compound = first + second

    first_message = SMB2Message.from_bytes(compound)
    second_message = SMB2Message.from_bytes(compound[first_length:])

    assert first_length % 8 == 0
    assert first_message.header.NextCommand == first_length
    assert isinstance(first_message.command, ECHO_REQ)
    assert second_message.header.NextCommand == 0
    assert second_message.header.MessageId == 2
    assert isinstance(second_message.command, LOGOFF_REQ)


@pytest.mark.parametrize(
    "parser, wire",
    [
        (
            lambda value: SMB2Message.from_bytes(value),
            b"\x00SMB" + b"\x00" * 64,
        ),
        (
            lambda value: SMB2Transform.from_bytes(value),
            b"\xfeSMB" + b"\x00" * 64,
        ),
        (
            lambda value: SMB2Compression.from_bytes(value),
            b"\xfdSMB" + b"\x00" * 64,
        ),
    ],
    ids=["smb2-message", "transform-envelope", "compression-envelope"],
)
def test_envelopes_reject_wrong_protocol_discriminators(parser, wire):
    with pytest.raises((AssertionError, Exception)):
        parser(wire)


def test_sync_header_rejects_wrong_structure_size():
    malformed = bytearray(_sync_header(SMB2Command.ECHO))
    malformed[4:6] = b"\x3f\x00"

    with pytest.raises(AssertionError):
        SMB2Header_SYNC.from_buffer(io.BytesIO(malformed))


@pytest.mark.xfail(
    reason="KF-0201: SMB2 fixed header parser accepts a 63-byte header",
    strict=True,
)
def test_sync_header_rejects_truncated_fixed_header():
    with pytest.raises(Exception):
        SMB2Header_SYNC.from_buffer(
            io.BytesIO(_sync_header(SMB2Command.ECHO)[:-1])
        )


@pytest.mark.xfail(
    reason="KF-0202: malformed command dispatch masks parse errors with NameError",
    strict=True,
)
def test_message_dispatch_rejects_malformed_command_body():
    malformed = _sync_header(SMB2Command.ECHO) + b"\x03\x00\x00\x00"

    with pytest.raises((AssertionError, ValueError)):
        SMB2Message.from_bytes(malformed)
