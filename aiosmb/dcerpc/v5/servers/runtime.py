"""Minimal connection-oriented DCE/RPC server runtime.

The runtime intentionally supports only little-endian NDR32 with no RPC
authentication.  It is transport agnostic: callers feed arbitrary byte-stream
chunks to :meth:`DCERPCServerRuntime.feed_data` and write the returned PDUs to
their transport.
"""

import inspect
import struct
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple

from aiosmb.dcerpc.v5.rpcrt import (
    DCERPC,
    MSRPC_ALTERCTX,
    MSRPC_ALTERCTX_R,
    MSRPC_BIND,
    MSRPC_BINDACK,
    MSRPC_FAULT,
    MSRPC_REQUEST,
    MSRPC_RESPONSE,
    MSRPC_CONT_RESULT_ACCEPT,
    MSRPC_CONT_RESULT_PROV_REJECT,
    PFC_FIRST_FRAG,
    PFC_LAST_FRAG,
    PFC_OBJECT_UUID,
)
from aiosmb.dcerpc.v5.uuid import uuidtup_to_bin


NCA_S_OP_RNG_ERROR = 0x1C010002
NCA_S_UNK_IF = 0x1C010003
NCA_S_PROTO_ERROR = 0x1C01000B
NCA_S_INVALID_PRES_CONTEXT_ID = 0x1C00001C
NCA_S_UNSUPPORTED_AUTHN_LEVEL = 0x1C00001D
RPC_X_BAD_STUB_DATA = 0x000006F7

_COMMON_HEADER_SIZE = 16
_REQUEST_HEADER_SIZE = 24
_RESPONSE_HEADER_SIZE = 24
_MIN_FRAGMENT_SIZE = _RESPONSE_HEADER_SIZE + 1


class DCERPCProtocolError(ValueError):
    """Raised when an input byte stream cannot contain a valid CO PDU."""


class DCERPCFault(Exception):
    """Ask the runtime to return a specific DCE/RPC fault status."""

    def __init__(self, status: int):
        super().__init__("DCE/RPC fault 0x%08x" % status)
        self.status = status


@dataclass(frozen=True)
class PresentationContext:
    context_id: int
    abstract_syntax: bytes
    transfer_syntax: bytes


@dataclass
class _Interface:
    syntax: bytes
    handlers: Dict[int, Callable[[bytes], Any]] = field(default_factory=dict)


@dataclass
class _PendingCall:
    call_id: int
    context_id: int
    opnum: int
    alloc_hint: int
    object_uuid: Optional[bytes]
    stub: bytearray = field(default_factory=bytearray)


@dataclass(frozen=True)
class _Header:
    version_major: int
    version_minor: int
    packet_type: int
    flags: int
    representation: int
    fragment_length: int
    auth_length: int
    call_id: int


def _syntax_bytes(value: Any) -> bytes:
    if isinstance(value, tuple):
        value = uuidtup_to_bin(value)
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError("interface syntax must be a 20-byte value or UUID tuple")
    value = bytes(value)
    if len(value) != 20:
        raise ValueError("interface syntax must be exactly 20 bytes")
    return value


class DCERPCServerRuntime:
    """NDR32, connection-oriented DCE/RPC association state.

    Handlers are registered per abstract syntax and opnum.  A handler receives
    the reassembled request stub and may return bytes, an object exposing
    ``getData()``, or an awaitable resolving to either.
    """

    def __init__(
        self,
        max_xmit_frag: int = 4280,
        max_recv_frag: int = 4280,
        secondary_address: bytes = b"",
        association_group_id: int = 1,
    ):
        if max_xmit_frag < _MIN_FRAGMENT_SIZE:
            raise ValueError("max_xmit_frag is too small for a response PDU")
        if max_recv_frag < _REQUEST_HEADER_SIZE:
            raise ValueError("max_recv_frag is too small for a request PDU")
        if not 0 <= association_group_id <= 0xFFFFFFFF:
            raise ValueError("association_group_id must fit in 32 bits")

        if isinstance(secondary_address, str):
            secondary_address = secondary_address.encode("ascii")
        if not isinstance(secondary_address, (bytes, bytearray, memoryview)):
            raise TypeError("secondary_address must be bytes")
        secondary_address = bytes(secondary_address)
        if secondary_address and not secondary_address.endswith(b"\x00"):
            secondary_address += b"\x00"
        if len(secondary_address) > 0xFFFF:
            raise ValueError("secondary_address is too long")

        self.configured_max_xmit_frag = max_xmit_frag
        self.configured_max_recv_frag = max_recv_frag
        self.max_xmit_frag = max_xmit_frag
        self.max_recv_frag = max_recv_frag
        self.peer_max_xmit_frag = max_recv_frag
        self.peer_max_recv_frag = max_xmit_frag
        self.secondary_address = secondary_address
        self.association_group_id = association_group_id

        self.interfaces: Dict[bytes, _Interface] = {}
        self.contexts: Dict[int, PresentationContext] = {}
        self.pending_calls: Dict[int, _PendingCall] = {}
        self.last_call_id: Optional[int] = None
        self.bound = False
        self._input_buffer = bytearray()

    def register_interface(
        self,
        interface_syntax: Any,
        handlers: Mapping[int, Callable[[bytes], Any]],
    ) -> None:
        """Register or replace handlers for one interface UUID/version."""

        syntax = _syntax_bytes(interface_syntax)
        normalized: Dict[int, Callable[[bytes], Any]] = {}
        for opnum, handler in handlers.items():
            if not isinstance(opnum, int) or not 0 <= opnum <= 0xFFFF:
                raise ValueError("opnum must fit in 16 bits")
            if not callable(handler):
                raise TypeError("DCE/RPC handlers must be callable")
            normalized[opnum] = handler
        self.interfaces[syntax] = _Interface(syntax, normalized)

    def unregister_interface(self, interface_syntax: Any) -> None:
        syntax = _syntax_bytes(interface_syntax)
        self.interfaces.pop(syntax, None)
        self.contexts = {
            context_id: context
            for context_id, context in self.contexts.items()
            if context.abstract_syntax != syntax
        }

    def reset(self) -> None:
        """Reset association state while preserving registered interfaces."""

        self.max_xmit_frag = self.configured_max_xmit_frag
        self.max_recv_frag = self.configured_max_recv_frag
        self.peer_max_xmit_frag = self.configured_max_recv_frag
        self.peer_max_recv_frag = self.configured_max_xmit_frag
        self.contexts.clear()
        self.pending_calls.clear()
        self.last_call_id = None
        self.bound = False
        self._input_buffer.clear()

    async def feed_data(self, data: bytes) -> List[bytes]:
        """Consume a byte-stream chunk and return all complete reply PDUs."""

        if data is None:
            return []
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("DCE/RPC input must be bytes")
        self._input_buffer.extend(data)
        replies: List[bytes] = []

        while len(self._input_buffer) >= _COMMON_HEADER_SIZE:
            fragment_length = struct.unpack_from("<H", self._input_buffer, 8)[0]
            if fragment_length < _COMMON_HEADER_SIZE:
                self._input_buffer.clear()
                raise DCERPCProtocolError(
                    "DCE/RPC fragment length is shorter than its common header"
                )
            if fragment_length > 0xFFFF:
                self._input_buffer.clear()
                raise DCERPCProtocolError("DCE/RPC fragment length exceeds 16 bits")
            if len(self._input_buffer) < fragment_length:
                break

            pdu = bytes(self._input_buffer[:fragment_length])
            del self._input_buffer[:fragment_length]
            replies.extend(await self.handle_pdu(pdu))

        return replies

    async def handle_pdu(self, pdu: bytes) -> List[bytes]:
        """Process one complete PDU and return zero or more reply PDUs."""

        header = self._parse_header(pdu)
        self.last_call_id = header.call_id

        if header.version_major != 5 or header.version_minor != 0:
            return [self._fault(header.call_id, 0, NCA_S_PROTO_ERROR)]
        if header.representation != 0x10:
            return [self._fault(header.call_id, 0, NCA_S_PROTO_ERROR)]
        if header.auth_length:
            return [
                self._fault(
                    header.call_id,
                    self._request_context_id(pdu, header),
                    NCA_S_UNSUPPORTED_AUTHN_LEVEL,
                )
            ]

        if header.packet_type in (MSRPC_BIND, MSRPC_ALTERCTX):
            return [self._handle_bind(pdu, header)]
        if header.packet_type == MSRPC_REQUEST:
            return await self._handle_request(pdu, header)
        return [self._fault(header.call_id, 0, NCA_S_PROTO_ERROR)]

    async def serve(self, transport: Any) -> None:
        """Serve a transport exposing async ``read`` and ``write`` methods."""

        while True:
            data = await transport.read()
            if data is None:
                break
            for response in await self.feed_data(data):
                await transport.write(response)

    @staticmethod
    def _parse_header(pdu: bytes) -> _Header:
        if not isinstance(pdu, (bytes, bytearray, memoryview)):
            raise TypeError("DCE/RPC PDU must be bytes")
        if len(pdu) < _COMMON_HEADER_SIZE:
            raise DCERPCProtocolError("truncated DCE/RPC common header")
        values = struct.unpack_from("<BBBBIHHI", pdu)
        header = _Header(*values)
        if header.fragment_length != len(pdu):
            raise DCERPCProtocolError(
                "DCE/RPC fragment length does not match supplied PDU"
            )
        if header.fragment_length < _COMMON_HEADER_SIZE:
            raise DCERPCProtocolError("invalid DCE/RPC fragment length")
        if header.auth_length + 8 > header.fragment_length:
            raise DCERPCProtocolError("invalid DCE/RPC authentication length")
        return header

    @staticmethod
    def _request_context_id(pdu: bytes, header: _Header) -> int:
        if (
            header.packet_type == MSRPC_REQUEST
            and header.fragment_length >= _REQUEST_HEADER_SIZE
        ):
            return struct.unpack_from("<H", pdu, 20)[0]
        return 0

    def _handle_bind(self, pdu: bytes, header: _Header) -> bytes:
        response_type = (
            MSRPC_BINDACK if header.packet_type == MSRPC_BIND else MSRPC_ALTERCTX_R
        )
        if header.flags & (PFC_FIRST_FRAG | PFC_LAST_FRAG) != (
            PFC_FIRST_FRAG | PFC_LAST_FRAG
        ):
            return self._fault(header.call_id, 0, NCA_S_PROTO_ERROR)
        if header.packet_type == MSRPC_ALTERCTX and not self.bound:
            return self._fault(header.call_id, 0, NCA_S_PROTO_ERROR)

        body_end = header.fragment_length
        body = pdu[_COMMON_HEADER_SIZE:body_end]
        try:
            (
                peer_max_xmit,
                peer_max_recv,
                _association_group,
                contexts,
            ) = self._parse_bind_body(body)
        except (DCERPCProtocolError, struct.error):
            return self._fault(header.call_id, 0, NCA_S_PROTO_ERROR)

        if header.packet_type == MSRPC_BIND:
            self.contexts.clear()
            self.pending_calls.clear()
            if (
                peer_max_xmit < _REQUEST_HEADER_SIZE
                or peer_max_recv < _MIN_FRAGMENT_SIZE
            ):
                return self._fault(header.call_id, 0, NCA_S_PROTO_ERROR)
            self.peer_max_xmit_frag = peer_max_xmit
            self.peer_max_recv_frag = peer_max_recv
            self.max_recv_frag = min(
                self.configured_max_recv_frag, peer_max_xmit
            )
            self.max_xmit_frag = min(
                self.configured_max_xmit_frag, peer_max_recv
            )

        results: List[Tuple[int, int, bytes]] = []
        for context_id, abstract_syntax, transfer_syntaxes in contexts:
            if abstract_syntax not in self.interfaces:
                results.append(
                    (
                        MSRPC_CONT_RESULT_PROV_REJECT,
                        1,
                        b"\x00" * 20,
                    )
                )
                continue
            if DCERPC.NDRSyntax not in transfer_syntaxes:
                results.append(
                    (
                        MSRPC_CONT_RESULT_PROV_REJECT,
                        2,
                        b"\x00" * 20,
                    )
                )
                continue

            self.contexts[context_id] = PresentationContext(
                context_id,
                abstract_syntax,
                DCERPC.NDRSyntax,
            )
            results.append(
                (
                    MSRPC_CONT_RESULT_ACCEPT,
                    0,
                    DCERPC.NDRSyntax,
                )
            )

        self.bound = True
        return self._bind_ack(header.call_id, response_type, results)

    @staticmethod
    def _parse_bind_body(
        body: bytes,
    ) -> Tuple[int, int, int, List[Tuple[int, bytes, List[bytes]]]]:
        if len(body) < 12:
            raise DCERPCProtocolError("truncated bind body")
        max_xmit, max_recv, association_group = struct.unpack_from("<HHI", body)
        context_count = body[8]
        cursor = 12
        contexts: List[Tuple[int, bytes, List[bytes]]] = []

        for _ in range(context_count):
            if cursor + 24 > len(body):
                raise DCERPCProtocolError("truncated presentation context")
            context_id, transfer_count, _reserved = struct.unpack_from(
                "<HBB", body, cursor
            )
            abstract_syntax = body[cursor + 4 : cursor + 24]
            cursor += 24
            if transfer_count == 0:
                raise DCERPCProtocolError(
                    "presentation context has no transfer syntax"
                )
            transfer_length = transfer_count * 20
            if cursor + transfer_length > len(body):
                raise DCERPCProtocolError("truncated transfer syntax list")
            transfer_syntaxes = [
                body[offset : offset + 20]
                for offset in range(cursor, cursor + transfer_length, 20)
            ]
            cursor += transfer_length
            contexts.append(
                (context_id, abstract_syntax, transfer_syntaxes)
            )

        if cursor != len(body):
            raise DCERPCProtocolError("unexpected trailing bind data")
        return max_xmit, max_recv, association_group, contexts

    def _bind_ack(
        self,
        call_id: int,
        packet_type: int,
        results: Iterable[Tuple[int, int, bytes]],
    ) -> bytes:
        result_list = list(results)
        body = struct.pack(
            "<HHIH",
            self.max_xmit_frag,
            self.max_recv_frag,
            self.association_group_id,
            len(self.secondary_address),
        )
        body += self.secondary_address
        body += b"\x00" * ((4 - ((_COMMON_HEADER_SIZE + len(body)) % 4)) % 4)
        body += struct.pack("<BBH", len(result_list), 0, 0)
        for result, reason, transfer_syntax in result_list:
            body += struct.pack("<HH", result, reason)
            body += transfer_syntax
        return self._common_header(
            packet_type,
            PFC_FIRST_FRAG | PFC_LAST_FRAG,
            call_id,
            len(body),
        ) + body

    async def _handle_request(
        self, pdu: bytes, header: _Header
    ) -> List[bytes]:
        header_size = _REQUEST_HEADER_SIZE
        if header.flags & PFC_OBJECT_UUID:
            header_size += 16
        if header.fragment_length < header_size:
            return [self._fault(header.call_id, 0, NCA_S_PROTO_ERROR)]
        if header.fragment_length > self.max_recv_frag:
            return [self._fault(header.call_id, 0, NCA_S_PROTO_ERROR)]

        alloc_hint, context_id, opnum = struct.unpack_from("<IHH", pdu, 16)
        object_uuid = (
            pdu[_REQUEST_HEADER_SIZE:header_size]
            if header.flags & PFC_OBJECT_UUID
            else None
        )
        stub_end = header.fragment_length
        stub = pdu[header_size:stub_end]
        first = bool(header.flags & PFC_FIRST_FRAG)
        last = bool(header.flags & PFC_LAST_FRAG)

        if first:
            if header.call_id in self.pending_calls:
                self.pending_calls.pop(header.call_id, None)
                return [
                    self._fault(header.call_id, context_id, NCA_S_PROTO_ERROR)
                ]
            pending = _PendingCall(
                header.call_id,
                context_id,
                opnum,
                alloc_hint,
                object_uuid,
            )
            self.pending_calls[header.call_id] = pending
        else:
            pending = self.pending_calls.get(header.call_id)
            if pending is None:
                return [
                    self._fault(header.call_id, context_id, NCA_S_PROTO_ERROR)
                ]
            if (
                pending.context_id != context_id
                or pending.opnum != opnum
                or pending.object_uuid != object_uuid
            ):
                self.pending_calls.pop(header.call_id, None)
                return [
                    self._fault(header.call_id, context_id, NCA_S_PROTO_ERROR)
                ]

        pending.stub.extend(stub)
        if not last:
            return []
        self.pending_calls.pop(header.call_id, None)

        context = self.contexts.get(context_id)
        if context is None:
            return [
                self._fault(
                    header.call_id,
                    context_id,
                    NCA_S_INVALID_PRES_CONTEXT_ID,
                )
            ]
        interface = self.interfaces.get(context.abstract_syntax)
        if interface is None:
            return [self._fault(header.call_id, context_id, NCA_S_UNK_IF)]
        handler = interface.handlers.get(opnum)
        if handler is None:
            return [
                self._fault(header.call_id, context_id, NCA_S_OP_RNG_ERROR)
            ]

        try:
            response = handler(bytes(pending.stub))
            if inspect.isawaitable(response):
                response = await response
            response_stub = self._response_bytes(response)
        except DCERPCFault as error:
            return [self._fault(header.call_id, context_id, error.status)]
        except Exception:
            return [
                self._fault(header.call_id, context_id, RPC_X_BAD_STUB_DATA)
            ]
        return self._response_fragments(
            header.call_id, context_id, response_stub
        )

    @staticmethod
    def _response_bytes(response: Any) -> bytes:
        if response is None:
            return b""
        if hasattr(response, "getData"):
            response = response.getData()
        if not isinstance(response, (bytes, bytearray, memoryview)):
            raise TypeError("DCE/RPC handler response must serialize to bytes")
        return bytes(response)

    def _response_fragments(
        self, call_id: int, context_id: int, stub: bytes
    ) -> List[bytes]:
        payload_size = self.max_xmit_frag - _RESPONSE_HEADER_SIZE
        if payload_size <= 0:
            return [self._fault(call_id, context_id, NCA_S_PROTO_ERROR)]

        chunks = [
            stub[offset : offset + payload_size]
            for offset in range(0, len(stub), payload_size)
        ]
        if not chunks:
            chunks = [b""]

        fragments: List[bytes] = []
        consumed = 0
        for index, chunk in enumerate(chunks):
            flags = 0
            if index == 0:
                flags |= PFC_FIRST_FRAG
            if index == len(chunks) - 1:
                flags |= PFC_LAST_FRAG
            alloc_hint = len(stub) - consumed
            body = struct.pack("<IHBB", alloc_hint, context_id, 0, 0) + chunk
            fragments.append(
                self._common_header(
                    MSRPC_RESPONSE,
                    flags,
                    call_id,
                    len(body),
                )
                + body
            )
            consumed += len(chunk)
        return fragments

    def _fault(self, call_id: int, context_id: int, status: int) -> bytes:
        body = struct.pack("<IHBBII", 8, context_id, 0, 0, status, 0)
        return self._common_header(
            MSRPC_FAULT,
            PFC_FIRST_FRAG | PFC_LAST_FRAG,
            call_id,
            len(body),
        ) + body

    @staticmethod
    def _common_header(
        packet_type: int,
        flags: int,
        call_id: int,
        body_length: int,
    ) -> bytes:
        fragment_length = _COMMON_HEADER_SIZE + body_length
        if fragment_length > 0xFFFF:
            raise ValueError("DCE/RPC fragment exceeds the 16-bit wire limit")
        return struct.pack(
            "<BBBBIHHI",
            5,
            0,
            packet_type,
            flags,
            0x10,
            fragment_length,
            0,
            call_id,
        )
