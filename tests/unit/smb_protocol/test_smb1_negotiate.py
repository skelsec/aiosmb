"""Deterministic SMB1 negotiate probe wire vectors."""

import struct

import pytest

from aiosmb.protocol.smb.command_codes import SMBCommand
from aiosmb.protocol.smb.commands.negotiate import (
    SMB_COM_NEGOTIATE_REPLY,
    SMB_COM_NEGOTIATE_REQ,
)
from aiosmb.protocol.smb.header import (
    SMBHeader,
    SMBHeaderFlags2Enum,
    SMBHeaderFlagsEnum,
)
from aiosmb.protocol.smb.message import SMBMessage
from aiosmb.wintypes.ntstatus import NTStatus


pytestmark = pytest.mark.unit


SMB1_REQUEST_HEADER = bytes.fromhex(
    "ff534d42"
    "72"
    "00000000"
    "18"
    "01c8"
    "3412"
    "0000000000000000"
    "0000"
    "efbe"
    "7856"
    "bc9a"
    "3412"
)

SMB1_DIALECT_DATA = (
    b"\x02NT LM 0.12\x00"
    b"\x02SMB 2.002\x00"
    b"\x02SMB 2.???\x00"
)
SMB1_NEGOTIATE_REQUEST = (
    SMB1_REQUEST_HEADER
    + b"\x00"
    + len(SMB1_DIALECT_DATA).to_bytes(2, "little")
    + SMB1_DIALECT_DATA
)


def _reply_header():
    return struct.pack(
        "<4sBIBHH8sHHHHH",
        b"\xffSMB",
        SMBCommand.SMB_COM_NEGOTIATE.value,
        NTStatus.SUCCESS.value,
        SMBHeaderFlagsEnum.SMB_FLAGS_REPLY.value,
        (
            SMBHeaderFlags2Enum.SMB_FLAGS2_LONG_NAMES
            | SMBHeaderFlags2Enum.SMB_FLAGS2_NT_STATUS
        ).value,
        0,
        b"\x00" * 8,
        0,
        0,
        0x5678,
        0,
        0x1234,
    )


def test_smb1_negotiate_request_golden_round_trip_and_dispatch():
    message = SMBMessage.from_bytes(SMB1_NEGOTIATE_REQUEST)

    assert message.header.Command is SMBCommand.SMB_COM_NEGOTIATE
    assert message.header.PIDHigh == 0x1234
    assert message.header.TID == 0xBEEF
    assert message.header.PIDLow == 0x5678
    assert message.header.UID == 0x9ABC
    assert message.header.MessageId == 0x1234
    assert isinstance(message.command, SMB_COM_NEGOTIATE_REQ)
    assert message.command.WordCount == 0
    assert message.command.ByteCount == len(SMB1_DIALECT_DATA)
    assert message.command.Dialects == [
        "NT LM 0.12",
        "SMB 2.002",
        "SMB 2.???",
    ]
    assert message.to_bytes() == SMB1_NEGOTIATE_REQUEST


def test_smb1_negotiate_request_encoder_matches_golden_body():
    request = SMB_COM_NEGOTIATE_REQ()
    request.Dialects = ["NT LM 0.12", "SMB 2.002", "SMB 2.???"]

    assert request.to_bytes() == SMB1_NEGOTIATE_REQUEST[32:]


def test_smb1_negotiate_reply_probe_dispatches_and_decodes():
    challenge = bytes.fromhex("0011223344556677")
    domain = "WORKGROUP\x00".encode("utf-16-le")
    variable = challenge + domain
    body = b"".join(
        [
            b"\x11",
            struct.pack("<H", 1),
            b"\x03",
            struct.pack("<HHII", 50, 1, 65535, 65535),
            bytes.fromhex("78563412"),
            struct.pack("<I", 0x80000000),
            bytes.fromhex("00e05776f4c7d601"),
            struct.pack("<H", 0),
            bytes([len(challenge)]),
            struct.pack("<H", len(variable)),
            variable,
        ]
    )

    message = SMBMessage.from_bytes(_reply_header() + body)

    assert isinstance(message.command, SMB_COM_NEGOTIATE_REPLY)
    assert message.command.WordCount == 17
    assert message.command.DialectIndex == 1
    assert message.command.MaxMpxCount == 50
    assert message.command.MaxBufferSize == 65535
    assert message.command.Challenge == challenge
    assert message.command.DomainName == domain


@pytest.mark.parametrize(
    "body",
    [
        b"\x00\x04\x00\x03BAD",
        b"\x00\x04\x00\x02BAD",
    ],
    ids=["wrong-dialect-marker", "unterminated-dialect"],
)
def test_smb1_negotiate_rejects_malformed_dialect_lists(body):
    with pytest.raises(Exception):
        SMB_COM_NEGOTIATE_REQ.from_bytes(body)


def test_smb1_header_rejects_wrong_protocol_magic():
    with pytest.raises(AssertionError, match="Magic incorrect"):
        SMBHeader.from_bytes(b"\x00" + SMB1_REQUEST_HEADER[1:])


@pytest.mark.xfail(
    reason="KF-0200: SMB1 fixed header parser accepts a truncated MessageId",
    strict=True,
)
def test_smb1_header_rejects_truncated_fixed_header():
    with pytest.raises(Exception):
        SMBHeader.from_bytes(SMB1_REQUEST_HEADER[:-1])
