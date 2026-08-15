"""SMB 3.1.1 negotiate and create-context alignment coverage."""

import io
import struct

import pytest

from aiosmb.protocol.common import NegotiateDialects
from aiosmb.protocol.smb2.command_codes import SMB2Command
from aiosmb.protocol.smb2.commands.create import CREATE_CONTEXT
from aiosmb.protocol.smb2.commands.negotiate import (
    NEGOTIATE_REQ,
    NegotiateCapabilities,
    NegotiateSecurityMode,
    SMB2Cipher,
    SMB2CompressionCapabilities,
    SMB2CompressionFlags,
    SMB2CompressionType,
    SMB2ContextType,
    SMB2EncryptionCapabilities,
    SMB2HashAlgorithm,
    SMB2NegotiateContext,
    SMB2PreauthIntegrityCapabilities,
    SMB2SigningAlgorithm,
    SMB2SigningCapabilities,
)
from aiosmb.protocol.smb2.message import SMB2Message
from aiosmb.wintypes.dtyp.constrcuted_security.guid import GUID


pytestmark = pytest.mark.unit


def _guid(wire):
    guid = GUID()
    guid.Data1 = wire[0:4]
    guid.Data2 = wire[4:6]
    guid.Data3 = wire[6:8]
    guid.Data4 = wire[8:16]
    return guid


def _negotiate_header():
    return struct.pack(
        "<4sHHIHHIIQIIQ16s",
        b"\xfeSMB",
        64,
        1,
        0,
        SMB2Command.NEGOTIATE.value,
        1,
        0,
        0,
        1,
        0,
        0,
        0,
        b"\x00" * 16,
    )


def test_preauth_context_matches_golden_and_round_trips():
    golden = bytes.fromhex(
        "0100"
        "0a00"
        "00000000"
        "0100"
        "0400"
        "0100"
        "73616c74"
    )

    context = SMB2PreauthIntegrityCapabilities.from_buffer(io.BytesIO(golden))

    assert context.ContextType is SMB2ContextType.PREAUTH_INTEGRITY_CAPABILITIES
    assert context.DataLength == 10
    assert context.HashAlgorithms == [SMB2HashAlgorithm.SHA_512]
    assert context.Salt == b"salt"
    assert context.to_bytes() == golden


def test_encryption_and_signing_contexts_round_trip():
    encryption = SMB2EncryptionCapabilities.from_enc_list(
        [SMB2Cipher.AES_128_GCM, SMB2Cipher.AES_256_GCM]
    )
    signing = SMB2SigningCapabilities.from_enc_list(
        [SMB2SigningAlgorithm.AES_CMAC, SMB2SigningAlgorithm.AES_GMAC]
    )

    encryption_wire = encryption.to_bytes()
    signing_wire = signing.to_bytes()
    parsed_encryption = SMB2EncryptionCapabilities.from_buffer(
        io.BytesIO(encryption_wire)
    )
    parsed_signing = SMB2SigningCapabilities.from_buffer(
        io.BytesIO(signing_wire)
    )

    assert parsed_encryption.Ciphers == [
        SMB2Cipher.AES_128_GCM,
        SMB2Cipher.AES_256_GCM,
    ]
    assert parsed_encryption.to_bytes() == encryption_wire
    assert parsed_signing.SigningAlgorithms == [
        SMB2SigningAlgorithm.AES_CMAC,
        SMB2SigningAlgorithm.AES_GMAC,
    ]
    assert parsed_signing.to_bytes() == signing_wire


def test_compression_context_decoder_accepts_spec_width_flags_golden():
    golden = (
        struct.pack("<HHI", SMB2ContextType.COMPRESSION_CAPABILITIES.value, 10, 0)
        + struct.pack(
            "<HHIH",
            1,
            0,
            SMB2CompressionFlags.CHAINED.value,
            SMB2CompressionType.LZNT1.value,
        )
    )

    context = SMB2CompressionCapabilities.from_buffer(io.BytesIO(golden))

    assert context.CompressionAlgorithmCount == 1
    assert context.Padding == 0
    assert context.Flags is SMB2CompressionFlags.CHAINED
    assert context.CompressionAlgorithms == [SMB2CompressionType.LZNT1]


def test_smb311_negotiate_context_offsets_and_alignment_dispatch():
    preauth = SMB2PreauthIntegrityCapabilities.construct(
        hash_algos=[SMB2HashAlgorithm.SHA_512],
        salt=b"x",
    )
    encryption = SMB2EncryptionCapabilities.from_enc_list(
        [SMB2Cipher.AES_128_GCM]
    )
    request = NEGOTIATE_REQ()
    request.SecurityMode = (
        NegotiateSecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED
    )
    request.Capabilities = (
        NegotiateCapabilities.DFS | NegotiateCapabilities.ENCRYPTION
    )
    request.ClientGuid = _guid(bytes(range(16)))
    request.Dialects = [NegotiateDialects.SMB311]
    request.NegotiateContextList = [preauth, encryption]

    body = request.to_bytes()
    context_offset = int.from_bytes(body[28:32], "little")
    first_length = len(preauth.to_bytes())
    second_offset = context_offset + first_length
    second_offset += (-second_offset) % 8
    message = SMB2Message.from_bytes(_negotiate_header() + body)

    assert context_offset == 104
    assert context_offset % 8 == 0
    assert second_offset % 8 == 0
    assert (
        int.from_bytes(
            (_negotiate_header() + body)[second_offset : second_offset + 2],
            "little",
        )
        == SMB2ContextType.ENCRYPTION_CAPABILITIES.value
    )
    assert isinstance(message.command, NEGOTIATE_REQ)
    assert message.command.NegotiateContextCount == 2
    assert len(message.command.NegotiateContextList) == 2
    assert isinstance(
        message.command.NegotiateContextList[0],
        SMB2PreauthIntegrityCapabilities,
    )
    assert isinstance(
        message.command.NegotiateContextList[1],
        SMB2EncryptionCapabilities,
    )


def test_create_context_name_data_offsets_and_chain_alignment():
    first = CREATE_CONTEXT("RqLs", b"12345678")
    second = CREATE_CONTEXT("MxAc", b"abcdefgh")
    buffer = io.BytesIO()

    first.to_buffer(buffer, is_last=False)
    second_start = buffer.tell()
    second.to_buffer(buffer, is_last=True)
    wire = buffer.getvalue()

    assert len(first.to_bytes()) == 32
    assert int.from_bytes(wire[0:4], "little") == second_start
    assert int.from_bytes(wire[4:6], "little") == 16
    assert int.from_bytes(wire[10:12], "little") == 24
    assert second_start == 32
    assert second_start % 8 == 0
    assert int.from_bytes(wire[second_start : second_start + 4], "little") == 0


def test_unknown_negotiate_context_type_is_rejected():
    with pytest.raises(ValueError):
        SMB2NegotiateContext.from_buffer(
            io.BytesIO(struct.pack("<HHI", 0x9999, 0, 0))
        )


def test_compression_context_encoder_round_trips():
    context = SMB2CompressionCapabilities.from_comp_list(
        [SMB2CompressionType.LZNT1],
        is_chained=True,
    )

    wire = context.to_bytes()
    parsed = SMB2CompressionCapabilities.from_buffer(io.BytesIO(wire))

    assert parsed.Flags is SMB2CompressionFlags.CHAINED
    assert parsed.CompressionAlgorithms == [SMB2CompressionType.LZNT1]


def test_compression_context_rejects_duplicate_algorithms():
    with pytest.raises(ValueError, match="unique"):
        SMB2CompressionCapabilities.from_comp_list(
            [SMB2CompressionType.LZ77, SMB2CompressionType.LZ77]
        )

    wire = (
        struct.pack(
            "<HHIHHI",
            SMB2ContextType.COMPRESSION_CAPABILITIES.value,
            12,
            0,
            2,
            0,
            SMB2CompressionFlags.NONE.value,
        )
        + struct.pack(
            "<HH",
            SMB2CompressionType.LZ77.value,
            SMB2CompressionType.LZ77.value,
        )
    )
    with pytest.raises(ValueError, match="duplicate"):
        SMB2CompressionCapabilities.from_buffer(io.BytesIO(wire))


@pytest.mark.xfail(
    reason="KF-0204: non-first CREATE_CONTEXT Next is absolute, not relative",
    strict=True,
)
def test_each_create_context_next_offset_is_structure_relative():
    contexts = [
        CREATE_CONTEXT("RqLs", b"12345678"),
        CREATE_CONTEXT("MxAc", b"abcdefgh"),
        CREATE_CONTEXT("QFid", b"ABCDEFGH"),
    ]
    buffer = io.BytesIO()

    starts = []
    for index, context in enumerate(contexts):
        starts.append(buffer.tell())
        context.to_buffer(buffer, is_last=index == len(contexts) - 1)
    wire = buffer.getvalue()

    second_start = starts[1]
    third_start = starts[2]
    assert int.from_bytes(
        wire[second_start : second_start + 4], "little"
    ) == third_start - second_start
