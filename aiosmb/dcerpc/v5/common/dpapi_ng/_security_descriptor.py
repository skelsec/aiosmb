# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import re
import typing as t


def sid_to_bytes(sid: str) -> bytes:
    sid_pattern = re.compile(r"^S-(\d)-(\d+)(?:-\d+){1,15}$")
    sid_match = sid_pattern.match(sid)
    if not sid_match:
        raise ValueError(f"Input string '{sid}' is not a valid SID string")

    sid_split = sid.split("-")
    revision = int(sid_split[1])
    authority = int(sid_split[2])

    data = bytearray(authority.to_bytes(8, byteorder="big"))
    data[0] = revision
    data[1] = len(sid_split) - 3

    for idx in range(3, len(sid_split)):
        sub_auth = int(sid_split[idx])
        data += sub_auth.to_bytes(4, byteorder="little")

    return bytes(data)


def ace_to_bytes(sid: str, access_mask: int) -> bytes:
    b_sid = sid_to_bytes(sid)

    return b"".join(
        [
            b"\x00\x00",  # AceType, AceFlags - ACCESS_ALLOWED_ACE_TYPE
            (8 + len(b_sid)).to_bytes(2, byteorder="little"),
            access_mask.to_bytes(4, byteorder="little"),
            b_sid,
        ]
    )


def acl_to_bytes(aces: t.List[bytes]) -> bytes:
    ace_data = b"".join(aces)

    return b"".join(
        [
            b"\x02\x00",  # AclRevision, Sbz1 - ACL_REVISION
            (8 + len(ace_data)).to_bytes(2, byteorder="little"),
            len(aces).to_bytes(2, byteorder="little"),
            b"\x00\x00",  # Sbz1
            ace_data,
        ]
    )


def sd_to_bytes(
    owner: str,
    group: str,
    sacl: t.Optional[t.List[bytes]] = None,
    dacl: t.Optional[t.List[bytes]] = None,
) -> bytes:
    control = 0b10000000 << 8  # Self-Relative

    # While MS-DTYP state there is no required order for the dynamic data, it
    # is important that the raw bytes are exactly what Microsoft uses on the
    # server side when it computes the seed key values. Luckily the footnote
    # give the correct order the MS-GKDI expects: Sacl, Dacl, Owner, Group
    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/11e1608c-6169-4fbc-9c33-373fc9b224f4#Appendix_A_72
    dynamic_data = bytearray()
    current_offset = 20  # Length of the SD header bytes

    sacl_offset = 0
    if sacl:
        sacl_bytes = acl_to_bytes(sacl)
        sacl_offset = current_offset
        current_offset += len(sacl_bytes)

        control |= 0b00010000  # SACL Present
        dynamic_data += sacl_bytes

    dacl_offset = 0
    if dacl:
        dacl_bytes = acl_to_bytes(dacl)
        dacl_offset = current_offset
        current_offset += len(dacl_bytes)

        control |= 0b00000100  # DACL Present
        dynamic_data += dacl_bytes

    owner_bytes = sid_to_bytes(owner)
    owner_offset = current_offset
    current_offset += len(owner_bytes)
    dynamic_data += owner_bytes

    group_bytes = sid_to_bytes(group)
    group_offset = current_offset
    dynamic_data += group_bytes

    return b"".join(
        [
            b"\x01\x00",  # Revision and Sbz1
            control.to_bytes(2, byteorder="little"),
            owner_offset.to_bytes(4, byteorder="little"),
            group_offset.to_bytes(4, byteorder="little"),
            sacl_offset.to_bytes(4, byteorder="little"),
            dacl_offset.to_bytes(4, byteorder="little"),
            dynamic_data,
        ]
    )
