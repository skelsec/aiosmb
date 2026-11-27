"""Numeric SMB2 wire checks that must not call production encoders.

These helpers exist because golden vectors generated from ``to_bytes()``
cannot catch a layout Windows rejects. They only read little-endian fields
and compare them to observed Windows STATUS_INVALID_PARAMETER rules and
MS-SMB2 offset arithmetic. Do not import ``CREATE_REQ.to_bytes`` here.
"""

from __future__ import annotations

from typing import List, Optional, Tuple


SMB2_HEADER_SIZE = 64
CREATE_REQUEST_FIXED_SIZE = 56
CREATE_NAME_OFFSET_FIELD = 44
CREATE_NAME_LENGTH_FIELD = 46
CREATE_CONTEXTS_OFFSET_FIELD = 48
CREATE_CONTEXTS_LENGTH_FIELD = 52
WINDOWS_EMPTY_CREATE_NAME_OFFSET = SMB2_HEADER_SIZE + CREATE_REQUEST_FIXED_SIZE
WINDOWS_EMPTY_CREATE_MIN_BODY = 57


def create_name_fields(body: bytes) -> Tuple[int, int, int, int]:
    if len(body) < CREATE_REQUEST_FIXED_SIZE:
        raise ValueError("CREATE body is shorter than its fixed 56-byte prefix")
    return (
        int.from_bytes(
            body[CREATE_NAME_OFFSET_FIELD:CREATE_NAME_OFFSET_FIELD + 2],
            "little",
        ),
        int.from_bytes(
            body[CREATE_NAME_LENGTH_FIELD:CREATE_NAME_LENGTH_FIELD + 2],
            "little",
        ),
        int.from_bytes(
            body[CREATE_CONTEXTS_OFFSET_FIELD:CREATE_CONTEXTS_OFFSET_FIELD + 4],
            "little",
        ),
        int.from_bytes(
            body[CREATE_CONTEXTS_LENGTH_FIELD:CREATE_CONTEXTS_LENGTH_FIELD + 4],
            "little",
        ),
    )


def smb2_relative_range(
    body: bytes, offset: int, length: int
) -> Optional[bytes]:
    """Return ``body[offset - 64:][:length]`` when the range is in-bounds."""
    if length == 0:
        return b""
    if offset < SMB2_HEADER_SIZE:
        return None
    start = offset - SMB2_HEADER_SIZE
    end = start + length
    if start < 0 or end > len(body):
        return None
    return body[start:end]


def windows_create_layout_errors(body: bytes) -> List[str]:
    """Return reasons Windows 2019 rejected this CREATE body in lab.

    Observed on GOAD ``192.168.56.10`` (SMB 3.1.1): a share-root open with
    ``NameLength == 0`` and no create contexts fails with
    ``STATUS_INVALID_PARAMETER`` unless ``NameOffset == 120`` and the body
    is at least 57 bytes.
    """
    errors: List[str] = []
    if len(body) < CREATE_REQUEST_FIXED_SIZE:
        return ["CREATE body is shorter than 56 bytes"]

    structure_size = int.from_bytes(body[0:2], "little")
    name_offset, name_length, ctx_offset, ctx_length = create_name_fields(body)
    if structure_size != 57:
        errors.append("StructureSize %s != 57" % structure_size)
    if name_length % 2:
        errors.append("NameLength %s is not UTF-16 aligned" % name_length)
    if name_length:
        if name_offset % 8:
            errors.append("NameOffset %s is not 8-byte aligned" % name_offset)
        if smb2_relative_range(body, name_offset, name_length) is None:
            errors.append("NameOffset/NameLength is outside the CREATE body")
    if ctx_length:
        if ctx_offset % 8:
            errors.append(
                "CreateContextsOffset %s is not 8-byte aligned" % ctx_offset
            )
        if smb2_relative_range(body, ctx_offset, ctx_length) is None:
            errors.append(
                "CreateContextsOffset/Length is outside the CREATE body"
            )
    if name_length == 0 and ctx_length == 0:
        if name_offset != WINDOWS_EMPTY_CREATE_NAME_OFFSET:
            errors.append(
                "empty-name NameOffset %s != %s "
                "(Windows returns STATUS_INVALID_PARAMETER)"
                % (name_offset, WINDOWS_EMPTY_CREATE_NAME_OFFSET)
            )
        if len(body) < WINDOWS_EMPTY_CREATE_MIN_BODY:
            errors.append(
                "empty-name CREATE body length %s < %s "
                "(Windows returns STATUS_INVALID_PARAMETER)"
                % (len(body), WINDOWS_EMPTY_CREATE_MIN_BODY)
            )
    return errors


def command_body_from_smb2_message(wire: bytes) -> bytes:
    if len(wire) < SMB2_HEADER_SIZE:
        raise ValueError("SMB2 message is shorter than its fixed header")
    if wire[0:4] != b"\xfeSMB":
        raise ValueError("Not an unencrypted SMB2 message")
    return wire[SMB2_HEADER_SIZE:]
