"""Scripted negotiate and tree/file bookkeeping paths."""

import asyncio
import datetime

import pytest

from aiosmb.connection import FileHandle, SMBConnectionStatus
from aiosmb.protocol.common import NegotiateDialects
from aiosmb.protocol.smb2.command_codes import SMB2Command
from aiosmb.protocol.smb2.commands import (
    CLOSE_REPLY,
    CREATE_REPLY,
    ECHO_REPLY,
    TREE_CONNECT_REPLY,
    TREE_DISCONNECT_REPLY,
)
from aiosmb.protocol.smb2.commands.close import CloseFlag
from aiosmb.protocol.smb2.commands.create import (
    CreateAction,
    CreateDisposition,
    CreateOptions,
    OplockLevel,
    ShareAccess,
)
from aiosmb.protocol.smb2.commands.negotiate import (
    NEGOTIATE_REPLY,
    NegotiateCapabilities,
    NegotiateSecurityMode,
    SMB2Cipher,
    SMB2ContextType,
    SMB2CompressionCapabilities,
    SMB2CompressionType,
    SMB2EncryptionCapabilities,
    SMB2HashAlgorithm,
    SMB2PreauthIntegrityCapabilities,
)
from aiosmb.protocol.smb2.commands.tree_connect import (
    ShareFlags,
    ShareType,
    TreeCapabilities,
)
from aiosmb.protocol.smb2.message import SMB2Message
from aiosmb.wintypes.access_mask import FileAccessMask
from aiosmb.wintypes.dtyp.constrcuted_security.guid import GUID
from aiosmb.wintypes.fscc.FileAttributes import FileAttributes
from tests.support.scripted_smb import ScriptedSMBTransport, connection_reader
from tests.support.smb_connection import make_connection, make_reply


pytestmark = [pytest.mark.fake_peer, pytest.mark.asyncio]
TIMEOUT = 0.75


def _tree_reply(message_id: int, tree_id: int, session_id: int) -> bytes:
    body = TREE_CONNECT_REPLY()
    body.ShareType = ShareType.DISK
    body.ShareFlags = ShareFlags.SMB2_SHAREFLAG_ENCRYPT_DATA
    body.Capabilities = (
        TreeCapabilities.SMB2_SHARE_CAP_DFS
        | TreeCapabilities.SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY
    )
    body.MaximalAccess = FileAccessMask.GENERIC_READ
    return make_reply(
        message_id,
        body,
        command=SMB2Command.TREE_CONNECT,
        tree_id=tree_id,
        session_id=session_id,
    ).to_bytes()


def _create_reply(
    message_id: int, tree_id: int, session_id: int, file_id: int
) -> bytes:
    body = CREATE_REPLY()
    body.OplockLevel = OplockLevel.SMB2_OPLOCK_LEVEL_NONE
    body.Flags = CreateOptions(0)
    body.CreateAction = CreateAction.FILE_OPENED
    body.CreationTime = 0
    body.LastAccessTime = 0
    body.LastWriteTime = 0
    body.ChangeTime = 0
    body.AllocationSize = 4096
    body.EndofFile = 12
    body.FileAttributes = FileAttributes.FILE_ATTRIBUTE_NORMAL
    body.FileId = file_id
    body.CreateContextsOffset = 0
    body.CreateContextsLength = 0
    return make_reply(
        message_id,
        body,
        command=SMB2Command.CREATE,
        tree_id=tree_id,
        session_id=session_id,
    ).to_bytes()


def _close_reply(message_id: int, tree_id: int, session_id: int) -> bytes:
    body = CLOSE_REPLY()
    body.Flags = CloseFlag.NONE
    return make_reply(
        message_id,
        body,
        command=SMB2Command.CLOSE,
        tree_id=tree_id,
        session_id=session_id,
    ).to_bytes()


def _tree_disconnect_reply(
    message_id: int, tree_id: int, session_id: int
) -> bytes:
    return make_reply(
        message_id,
        TREE_DISCONNECT_REPLY(),
        command=SMB2Command.TREE_DISCONNECT,
        tree_id=tree_id,
        session_id=session_id,
    ).to_bytes()


async def test_tree_create_close_and_disconnect_update_bookkeeping() -> None:
    connection = make_connection()
    connection.SessionId = 0x1234
    tree_id = 0x55
    first_file_id = 0x11112222333344445555666677778888
    second_file_id = 0x9999AAAABBBBCCCCDDDDEEEEFFFF0000
    created_file_ids = iter((first_file_id, second_file_id))

    def respond(wire_data: bytes, transport: ScriptedSMBTransport) -> bytes:
        request = SMB2Message.from_bytes(wire_data)
        message_id = request.header.MessageId
        command = request.header.Command
        if command == SMB2Command.TREE_CONNECT:
            return _tree_reply(message_id, tree_id, connection.SessionId)
        if command == SMB2Command.CREATE:
            return _create_reply(
                message_id,
                tree_id,
                connection.SessionId,
                next(created_file_ids),
            )
        if command == SMB2Command.CLOSE:
            return _close_reply(message_id, tree_id, connection.SessionId)
        if command == SMB2Command.TREE_DISCONNECT:
            return _tree_disconnect_reply(
                message_id, tree_id, connection.SessionId
            )
        raise AssertionError("unexpected scripted command: {!r}".format(command))

    share = r"\\fake-peer.invalid\data"
    transport = ScriptedSMBTransport([respond] * 5)

    async with connection_reader(connection, transport):
        tree, error = await asyncio.wait_for(
            connection.tree_connect(share), timeout=TIMEOUT
        )
        assert error is None
        assert tree.tree_id == tree_id
        assert tree.share_name == share
        assert tree.is_DFS is True
        assert tree.is_CA is True
        assert tree.encrypt is True
        assert connection.TreeConnectTable_id[tree_id] is tree
        assert connection.TreeConnectTable_share[share] is tree

        first, error = await asyncio.wait_for(
            connection.create(
                tree_id,
                "alpha.txt",
                FileAccessMask.GENERIC_READ,
                ShareAccess.FILE_SHARE_READ,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
                CreateDisposition.FILE_OPEN,
                FileAttributes.FILE_ATTRIBUTE_NORMAL,
            ),
            timeout=TIMEOUT,
        )
        assert error is None
        second, error = await asyncio.wait_for(
            connection.create(
                tree_id,
                "beta.txt",
                FileAccessMask.GENERIC_READ,
                ShareAccess.FILE_SHARE_READ,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
                CreateDisposition.FILE_OPEN,
                FileAttributes.FILE_ATTRIBUTE_NORMAL,
            ),
            timeout=TIMEOUT,
        )
        assert error is None
        assert (first, second) == (first_file_id, second_file_id)
        assert connection.FileHandleTable[first].file_name == "alpha.txt"
        assert connection.FileHandleTable[second].tree_id == tree_id

        result, error = await asyncio.wait_for(
            connection.close(tree_id, first), timeout=TIMEOUT
        )
        assert result is True
        assert error is None
        assert first not in connection.FileHandleTable
        assert second in connection.FileHandleTable

        result, error = await asyncio.wait_for(
            connection.tree_disconnect(tree_id), timeout=TIMEOUT
        )
        assert result is True
        assert error is None
        assert connection.FileHandleTable == {}
        assert connection.TreeConnectTable_id == {}
        assert connection.TreeConnectTable_share == {}
        assert transport.remaining_actions == 0


async def test_file_handle_factory_preserves_oplock_and_identity() -> None:
    file_id = 0x1234567890ABCDEF
    reply = make_reply(
        4,
        type("CreateBody", (), {"FileId": file_id})(),
        command=SMB2Command.CREATE,
        tree_id=7,
    )

    handle = FileHandle.from_create_reply(
        reply,
        tree_id=7,
        file_name="nested/path.txt",
        oplock_level=OplockLevel.SMB2_OPLOCK_LEVEL_EXCLUSIVE,
    )

    assert handle.file_id == file_id
    assert handle.tree_id == 7
    assert handle.file_name == "nested/path.txt"
    assert handle.oplock_level == OplockLevel.SMB2_OPLOCK_LEVEL_EXCLUSIVE
    assert handle.oplock.locked() is False


def _negotiate_reply(message_id: int) -> bytes:
    body = NEGOTIATE_REPLY()
    body.SecurityMode = NegotiateSecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED
    body.DialectRevision = NegotiateDialects.SMB210
    body.NegotiateContextCount = 0
    body.ServerGuid = GUID.from_string(
        "00112233-4455-6677-8899-aabbccddeeff"
    )
    body.Capabilities = (
        NegotiateCapabilities.LARGE_MTU | NegotiateCapabilities.LEASING
    )
    body.MaxTransactSize = 131072
    body.MaxReadSize = 262144
    body.MaxWriteSize = 524288
    body.SystemTime = datetime.datetime(2020, 1, 2, 3, 4, 5)
    body.ServerStartTime = datetime.datetime(2020, 1, 1)
    body.SecurityBuffer = b""
    body.NegotiateContextOffset = 0
    return make_reply(
        message_id,
        body,
        command=SMB2Command.NEGOTIATE,
    ).to_bytes()


def _negotiate_311_reply(message_id: int, algorithm) -> bytes:
    body = NEGOTIATE_REPLY()
    body.SecurityMode = NegotiateSecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED
    body.DialectRevision = NegotiateDialects.SMB311
    body.ServerGuid = GUID.from_string(
        "00112233-4455-6677-8899-aabbccddeeff"
    )
    body.Capabilities = NegotiateCapabilities.LARGE_MTU
    body.SystemTime = datetime.datetime(2020, 1, 2, 3, 4, 5)
    body.ServerStartTime = datetime.datetime(2020, 1, 1)
    body.SecurityBuffer = b""
    body.NegotiateContextOffset = 128
    algorithms = algorithm if isinstance(algorithm, list) else [algorithm]
    body.NegotiateContextList = [
        SMB2CompressionCapabilities.from_comp_list(algorithms)
    ]
    body.NegotiateContextCount = len(body.NegotiateContextList)
    return make_reply(
        message_id,
        body,
        command=SMB2Command.NEGOTIATE,
    ).to_bytes()


def _negotiate_311_preauth_reply(
    message_id: int,
    include_encryption: bool = False,
) -> bytes:
    body = NEGOTIATE_REPLY()
    body.SecurityMode = NegotiateSecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED
    body.DialectRevision = NegotiateDialects.SMB311
    body.ServerGuid = GUID.from_string(
        "00112233-4455-6677-8899-aabbccddeeff"
    )
    body.Capabilities = NegotiateCapabilities.LARGE_MTU
    if not include_encryption:
        body.Capabilities |= NegotiateCapabilities.ENCRYPTION
    body.SystemTime = datetime.datetime(2020, 1, 2, 3, 4, 5)
    body.ServerStartTime = datetime.datetime(2020, 1, 1)
    body.SecurityBuffer = b""
    body.NegotiateContextOffset = 128
    if include_encryption:
        body.NegotiateContextList = [
            SMB2EncryptionCapabilities.from_enc_list(
                [SMB2Cipher.AES_128_GCM]
            )
        ]
    else:
        body.NegotiateContextList = [
            SMB2PreauthIntegrityCapabilities.construct(
                [SMB2HashAlgorithm.SHA_512]
            )
        ]
    body.NegotiateContextCount = len(body.NegotiateContextList)
    return make_reply(
        message_id,
        body,
        command=SMB2Command.NEGOTIATE,
    ).to_bytes()


async def test_scripted_negotiate_populates_connection_contract() -> None:
    connection = make_connection(
        status=SMBConnectionStatus.NEGOTIATING,
        dialect=NegotiateDialects.SMB210,
    )
    connection.selected_dialect = None

    def negotiate_response(
        wire_data: bytes, transport: ScriptedSMBTransport
    ) -> bytes:
        request = SMB2Message.from_bytes(wire_data)
        assert request.header.Command == SMB2Command.NEGOTIATE
        assert request.command.Dialects == [NegotiateDialects.SMB210]
        return _negotiate_reply(request.header.MessageId)

    transport = ScriptedSMBTransport([negotiate_response])

    async with connection_reader(connection, transport):
        result, reply, error = await asyncio.wait_for(
            connection.negotiate(protocol_test=True), timeout=TIMEOUT
        )

        assert result is True
        assert error is None
        assert reply.command.DialectRevision == NegotiateDialects.SMB210
        assert connection.selected_dialect == NegotiateDialects.SMB210
        assert connection.status == SMBConnectionStatus.SESSIONSETUP
        assert connection.signing_required is True
        assert connection.SupportsMultiCredit is True
        assert connection.SupportsFileLeasing is True
        assert connection.MaxTransactSize == 131072
        assert connection.MaxReadSize == 262144
        assert connection.MaxWriteSize == 524288
        assert transport.packetizer.buffer_size == connection.MaxReadSize
        assert connection.PreauthIntegrityHashValue != b"\x00" * 64


async def test_smb311_encryption_opt_out_omits_capability_and_context() -> None:
    connection = make_connection(
        status=SMBConnectionStatus.NEGOTIATING,
        dialect=NegotiateDialects.SMB311,
        advertise_encryption=False,
    )
    connection.selected_dialect = None

    def negotiate_response(
        wire_data: bytes, transport: ScriptedSMBTransport
    ) -> bytes:
        request = SMB2Message.from_bytes(wire_data)
        assert request.header.Command == SMB2Command.NEGOTIATE
        assert not (
            request.command.Capabilities & NegotiateCapabilities.ENCRYPTION
        )
        context_types = [
            context.ContextType
            for context in request.command.NegotiateContextList
        ]
        assert SMB2ContextType.PREAUTH_INTEGRITY_CAPABILITIES in context_types
        assert SMB2ContextType.ENCRYPTION_CAPABILITIES not in context_types
        return _negotiate_311_preauth_reply(request.header.MessageId)

    transport = ScriptedSMBTransport([negotiate_response])

    async with connection_reader(connection, transport):
        result, _, error = await asyncio.wait_for(
            connection.negotiate(protocol_test=True),
            timeout=TIMEOUT,
        )

    assert error is None
    assert result is True
    assert connection.ClientCapabilities == 0
    assert (
        connection.ServerCapabilities & NegotiateCapabilities.ENCRYPTION
    )
    assert connection.SupportsEncryption is False
    assert connection.encryption_required is False
    assert connection.CipherId is None


async def test_smb311_negotiate_tracks_mutual_encryption_capability() -> None:
    connection = make_connection(
        status=SMBConnectionStatus.NEGOTIATING,
        dialect=NegotiateDialects.SMB311,
    )
    connection.selected_dialect = None

    def negotiate_response(
        wire_data: bytes, transport: ScriptedSMBTransport
    ) -> bytes:
        request = SMB2Message.from_bytes(wire_data)
        assert (
            request.command.Capabilities & NegotiateCapabilities.ENCRYPTION
        )
        encryption_contexts = [
            context
            for context in request.command.NegotiateContextList
            if isinstance(context, SMB2EncryptionCapabilities)
        ]
        assert len(encryption_contexts) == 1
        assert encryption_contexts[0].Ciphers == [
            SMB2Cipher.AES_128_GCM,
            SMB2Cipher.AES_128_CCM,
        ]
        return _negotiate_311_preauth_reply(
            request.header.MessageId,
            include_encryption=True,
        )

    transport = ScriptedSMBTransport([negotiate_response])

    async with connection_reader(connection, transport):
        result, _, error = await asyncio.wait_for(
            connection.negotiate(protocol_test=True),
            timeout=TIMEOUT,
        )

    assert error is None
    assert result is True
    assert not (
        connection.ServerCapabilities & NegotiateCapabilities.ENCRYPTION
    )
    assert connection.SupportsEncryption is True
    assert connection.encryption_required is True
    assert connection.CipherId is SMB2Cipher.AES_128_GCM


async def test_encryption_opt_out_sends_clear_post_auth_echo() -> None:
    connection = make_connection(
        dialect=NegotiateDialects.SMB311,
        advertise_encryption=False,
    )
    connection.SessionId = 7
    connection.CipherId = None
    connection.EncryptionKey = b"\x44" * 16
    connection.encryption_required = False

    def echo_response(
        wire_data: bytes, transport: ScriptedSMBTransport
    ) -> bytes:
        assert wire_data[:4] == b"\xfeSMB"
        request = SMB2Message.from_bytes(wire_data)
        assert request.header.Command == SMB2Command.ECHO
        return make_reply(
            request.header.MessageId,
            ECHO_REPLY(),
            command=SMB2Command.ECHO,
            session_id=connection.SessionId,
        ).to_bytes()

    transport = ScriptedSMBTransport([echo_response])

    async with connection_reader(connection, transport):
        result, error = await asyncio.wait_for(
            connection.echo(),
            timeout=TIMEOUT,
        )

    assert result is True
    assert error is None


async def test_session_setup_preserves_client_signing_requirement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = make_connection(
        status=SMBConnectionStatus.SESSIONSETUP,
        dialect=NegotiateDialects.SMB311,
    )
    captured = []
    stop = RuntimeError("stop after capturing session setup")

    class OneLegAuthenticator:
        async def authenticate(self, *args, **kwargs):
            return b"authentication-token", None, None

    async def capture_request(message, *args, **kwargs):
        captured.append(message)
        return None, stop

    connection.gssapi = OneLegAuthenticator()
    monkeypatch.setattr(connection, "sendSMB", capture_request)

    result, error = await connection.session_setup()

    assert result is False
    assert error is stop
    assert len(captured) == 1
    assert captured[0].command.SecurityMode == connection.ClientSecurityMode
    assert (
        NegotiateSecurityMode.SMB2_NEGOTIATE_SIGNING_REQUIRED
        in captured[0].command.SecurityMode
    )


async def test_smb311_negotiate_preserves_offer_order_and_server_subset() -> None:
    connection = make_connection(
        status=SMBConnectionStatus.NEGOTIATING,
        dialect=NegotiateDialects.SMB311,
    )
    connection.selected_dialect = None
    connection.CompressionIds = [
        SMB2CompressionType.LZ77,
        SMB2CompressionType.LZ77_Huffman,
        SMB2CompressionType.LZ4,
        SMB2CompressionType.LZNT1,
    ]

    def negotiate_response(
        wire_data: bytes,
        transport: ScriptedSMBTransport,
    ) -> bytes:
        request = SMB2Message.from_bytes(wire_data)
        compression = [
            context
            for context in request.command.NegotiateContextList
            if isinstance(context, SMB2CompressionCapabilities)
        ]
        assert len(compression) == 1
        assert compression[0].CompressionAlgorithms == [
            SMB2CompressionType.LZ77,
            SMB2CompressionType.LZ77_Huffman,
            SMB2CompressionType.LZ4,
            SMB2CompressionType.LZNT1,
        ]
        return _negotiate_311_reply(
            request.header.MessageId,
            [SMB2CompressionType.LZ4, SMB2CompressionType.LZ77],
        )

    transport = ScriptedSMBTransport([negotiate_response])

    async with connection_reader(connection, transport):
        result, _, error = await asyncio.wait_for(
            connection.negotiate(protocol_test=True),
            timeout=TIMEOUT,
        )

    assert error is None
    assert result is True
    assert connection.CompressionId is SMB2CompressionType.LZ4
    assert connection.CompressionIds == [
        SMB2CompressionType.LZ4,
        SMB2CompressionType.LZ77,
    ]
    assert connection.SupportsChainedCompression is False


async def test_smb311_negotiate_none_response_disables_compression() -> None:
    connection = make_connection(
        status=SMBConnectionStatus.NEGOTIATING,
        dialect=NegotiateDialects.SMB311,
    )
    connection.selected_dialect = None
    connection.CompressionIds = [SMB2CompressionType.LZ77]

    def negotiate_response(
        wire_data: bytes,
        transport: ScriptedSMBTransport,
    ) -> bytes:
        request = SMB2Message.from_bytes(wire_data)
        return _negotiate_311_reply(
            request.header.MessageId,
            SMB2CompressionType.NONE,
        )

    transport = ScriptedSMBTransport([negotiate_response])

    async with connection_reader(connection, transport):
        result, _, error = await asyncio.wait_for(
            connection.negotiate(protocol_test=True),
            timeout=TIMEOUT,
        )

    assert error is None
    assert result is True
    assert connection.CompressionId is None
    assert connection.CompressionIds is None


async def test_smb311_negotiate_rejects_duplicate_compression_contexts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = make_connection(
        status=SMBConnectionStatus.NEGOTIATING,
        dialect=NegotiateDialects.SMB311,
    )
    connection.selected_dialect = None
    connection.CompressionIds = [SMB2CompressionType.LZ77]
    reply = SMB2Message.from_bytes(
        _negotiate_311_reply(0, SMB2CompressionType.LZ77)
    )
    reply.command.NegotiateContextList.append(
        SMB2CompressionCapabilities.from_comp_list(
            [SMB2CompressionType.LZ77]
        )
    )

    async def fake_send(message):
        return 0, None

    async def fake_recv(message_id):
        return reply, b"duplicate compression context reply", None

    monkeypatch.setattr(connection, "sendSMB", fake_send)
    monkeypatch.setattr(connection, "recvSMB", fake_recv)
    result, response, error = await asyncio.wait_for(
        connection.negotiate(protocol_test=True),
        timeout=TIMEOUT,
    )

    assert result is False
    assert response is None
    assert error is None
