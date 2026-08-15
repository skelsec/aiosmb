"""Small builders around the production SMBConnection wire types."""

from typing import Any, Optional

from aiosmb.connection import SMBConnection, SMBConnectionStatus
from aiosmb.commons.connection.target import SMBTarget
from aiosmb.protocol.common import NegotiateDialects
from aiosmb.protocol.smb2.command_codes import SMB2Command
from aiosmb.protocol.smb2.headers import (
    SMB2Header_ASYNC,
    SMB2Header_SYNC,
    SMB2HeaderFlag,
)
from aiosmb.protocol.smb2.message import SMB2Message
from aiosmb.wintypes.ntstatus import NTStatus


def make_connection(
    status: SMBConnectionStatus = SMBConnectionStatus.RUNNING,
    dialect: NegotiateDialects = NegotiateDialects.SMB210,
) -> SMBConnection:
    target = SMBTarget(
        ip="127.0.0.1",
        hostname="fake-peer.invalid",
        domain="TEST",
        timeout=1,
    )
    target.preferred_dialects = {dialect: 1}
    connection = SMBConnection(None, target, preserve_gssapi=False)
    connection.status = status
    connection.selected_dialect = dialect
    connection.activity_at = None
    return connection


def make_request(
    body: Any,
    command: SMB2Command = SMB2Command.ECHO,
    credit_charge: int = 1,
    message_id: Optional[int] = None,
) -> SMB2Message:
    header = SMB2Header_SYNC()
    header.Command = command
    header.CreditCharge = credit_charge
    header.CreditReq = 0
    header.MessageId = message_id
    return SMB2Message(header, body)


def make_reply(
    message_id: int,
    body: Any,
    command: SMB2Command = SMB2Command.ECHO,
    status: NTStatus = NTStatus.SUCCESS,
    tree_id: int = 0,
    session_id: int = 0,
    async_id: Optional[bytes] = None,
) -> SMB2Message:
    flags = SMB2HeaderFlag.SMB2_FLAGS_SERVER_TO_REDIR
    if async_id is None:
        header = SMB2Header_SYNC()
        header.CreditCharge = 1
        header.Status = status
        header.Command = command
        header.CreditReq = 1
        header.Flags = flags
        header.MessageId = message_id
        header.TreeId = tree_id
        header.SessionId = session_id
    else:
        header = SMB2Header_ASYNC.construct(
            command,
            flags | SMB2HeaderFlag.SMB2_FLAGS_ASYNC_COMMAND,
            message_id,
            Credit=1,
            CreditCharge=1,
            AsyncId=async_id,
            SessionId=session_id.to_bytes(8, "little"),
            status=status,
        )
    return SMB2Message(header, body)
