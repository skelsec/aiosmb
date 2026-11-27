"""Offline parsing coverage for connection-oriented DCERPC PDUs."""

import importlib
import io
import json
from pathlib import Path
import subprocess
import sys
import types
import uuid

import pytest


pytestmark = pytest.mark.unit

_PROTOCOL_PACKAGE = "aiosmb.dcerpc.v5.protocol"


def _install_legacy_con_import_aliases():
    """Allow parser coverage while the canonical import defect remains visible."""
    legacy_name = _PROTOCOL_PACKAGE + ".con"
    legacy_package = types.ModuleType(legacy_name)
    legacy_package.__path__ = []
    sys.modules.setdefault(legacy_name, legacy_package)

    for module_name in ("constants", "commons"):
        module = importlib.import_module(
            _PROTOCOL_PACKAGE + ".conpdu." + module_name
        )
        sys.modules.setdefault(legacy_name + "." + module_name, module)


_install_legacy_con_import_aliases()

bind = importlib.import_module(_PROTOCOL_PACKAGE + ".conpdu.bind")
bindack = importlib.import_module(_PROTOCOL_PACKAGE + ".conpdu.bindack")
bindnack = importlib.import_module(_PROTOCOL_PACKAGE + ".conpdu.bindnack")
cancel = importlib.import_module(_PROTOCOL_PACKAGE + ".conpdu.cancel")
commons = importlib.import_module(_PROTOCOL_PACKAGE + ".conpdu.commons")
constants = importlib.import_module(_PROTOCOL_PACKAGE + ".conpdu.constants")


@pytest.fixture(scope="module")
def con_vectors():
    fixture_path = (
        Path(__file__).parents[2] / "fixtures" / "dcerpc" / "wire_vectors.json"
    )
    with fixture_path.open("r", encoding="utf-8") as fixture_file:
        values = json.load(fixture_file)["con_pdu"]
    return {name: bytes.fromhex(value) for name, value in values.items()}


@pytest.mark.xfail(
    strict=True,
    reason=(
        "KF-0400: CON PDU modules import the nonexistent protocol.con package"
    ),
)
def test_con_pdu_module_imports_without_test_aliases():
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            "import aiosmb.dcerpc.v5.protocol.conpdu.bind",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr


def test_presentation_syntax_decodes_uuid_and_version():
    wire = (
        bytes.fromhex("045d888aeb1cc9119fe808002b104860")
        + bytes.fromhex("02000000")
    )

    syntax = commons.PresentationSyntax.from_bytes(wire)

    assert syntax.if_uuid == uuid.UUID(
        "8a885d04-1ceb-11c9-9fe8-08002b104860"
    )
    assert syntax.if_version == 2
    assert "VERSION: 2" in repr(syntax)


def test_bind_pdu_decodes_context_and_transfer_syntax(con_vectors):
    pdu = bind.BINDPDU.from_bytes(con_vectors["bind"])

    assert pdu.rpc_vers == 5
    assert pdu.rpc_vers_minor == 0
    assert pdu.PTYPE is constants.PTYPE.BIND
    assert pdu.pfc_flags == (
        constants.PFC.FIRST_FRAG | constants.PFC.LAST_FRAG
    )
    assert pdu.packed_drep == b"\x10\x00\x00\x00"
    assert pdu.frag_length == len(con_vectors["bind"]) == 72
    assert pdu.auth_length == 0
    assert pdu.call_id == 1
    assert pdu.max_xmit_frag == 4280
    assert pdu.max_recv_frag == 4280
    assert pdu.assoc_group_id == b"\x00\x00\x00\x00"
    assert pdu.auth_verifier is None

    context_list = pdu.context_list
    assert context_list.n_context_elem == 1
    assert context_list.reserved == b"\x00"
    assert context_list.reserved2 == b"\x00\x00"
    assert len(context_list.results) == 1

    context = context_list.results[0]
    assert context.p_cont_id == 0
    assert context.n_transfer_syn == 1
    assert context.reserved == b"\x00"
    assert context.abstract_syntax.if_uuid == uuid.UUID(
        "4b324fc8-1670-01d3-1278-5a47bf6ee188"
    )
    assert context.abstract_syntax.if_version == 3
    assert len(context.transfer_syntaxes) == 1
    assert context.transfer_syntaxes[0].if_uuid == uuid.UUID(
        "8a885d04-1ceb-11c9-9fe8-08002b104860"
    )
    assert context.transfer_syntaxes[0].if_version == 2
    assert "BINDPDU" in str(pdu)


def test_bind_from_buffer_consumes_exactly_one_pdu(con_vectors):
    stream = io.BytesIO(con_vectors["bind"] + b"TAIL")

    bind.BINDPDU.from_buffer(stream)

    assert stream.tell() == len(con_vectors["bind"])
    assert stream.read() == b"TAIL"


def test_bind_ack_pdu_decodes_secondary_address_and_result(con_vectors):
    pdu = bindack.BINDACKPDU.from_bytes(con_vectors["bind_ack"])

    assert pdu.PTYPE is constants.PTYPE.BINDACK
    assert pdu.pfc_flags == (
        constants.PFC.FIRST_FRAG | constants.PFC.LAST_FRAG
    )
    assert pdu.frag_length == len(con_vectors["bind_ack"]) == 68
    assert pdu.auth_length == 0
    assert pdu.call_id == 1
    assert pdu.max_xmit_frag == 4280
    assert pdu.max_recv_frag == 4280
    assert pdu.assoc_group_id == b"\x12\x67\x00\x00"
    assert pdu.sec_addr.length == 13
    assert pdu.sec_addr.port_spec == "\\PIPE\\srvsvc\x00"
    assert pdu.pad2 == b"\x00"
    assert pdu.auth_verifier is None

    assert pdu.context_list.n_results == 1
    result = pdu.context_list.results[0]
    assert result.result is bindack.ResultEnum.ACCEPTANCE
    assert result.reason is bindack.ProviderReason.REASON_NOT_SPECIFIED
    assert result.transfer_syntax.if_uuid == uuid.UUID(
        "8a885d04-1ceb-11c9-9fe8-08002b104860"
    )
    assert result.transfer_syntax.if_version == 2
    assert "BINDACKPDU" in str(pdu)


@pytest.mark.xfail(
    strict=True,
    reason="KF-0403: PORT_ANY_T.__repr__ passes an extra argument to __str__",
)
def test_port_any_repr_matches_string_representation(con_vectors):
    port = bindack.BINDACKPDU.from_bytes(con_vectors["bind_ack"]).sec_addr

    assert repr(port) == str(port)


def test_bind_nack_pdu_decodes_provider_rejection(con_vectors):
    pdu = bindnack.BINDNACKPDU.from_bytes(con_vectors["bind_nack"])

    assert pdu.rpc_vers == 5
    assert pdu.PTYPE is constants.PTYPE.BINDNAK
    assert pdu.frag_length == len(con_vectors["bind_nack"]) == 18
    assert pdu.auth_length == 0
    assert pdu.call_id == 7
    assert pdu.provider_reject_reason is bindnack.RejectReason.LOCAL_LIMIT_EXCEEDED
    assert pdu.versions is None
    assert "LOCAL_LIMIT_EXCEEDED" in str(pdu)


def test_cancel_pdu_decodes_auth_verifier(con_vectors):
    pdu = cancel.CANCELPDU.from_bytes(con_vectors["cancel"])

    assert pdu.rpc_vers == 5
    assert pdu.PTYPE is constants.PTYPE.CO_CANCEL
    assert pdu.pfc_flags == (
        constants.PFC.FIRST_FRAG | constants.PFC.LAST_FRAG
    )
    assert pdu.frag_length == len(con_vectors["cancel"]) == 20
    assert pdu.auth_length == 4
    assert pdu.call_id == 0x12345678
    assert pdu.auth_verifier == bytes.fromhex("deadbeef")
    assert "CANCELPDU" in repr(pdu)


def test_pdu_enums_preserve_wire_values_and_flag_composition():
    assert constants.PTYPE.REQUEST.value == 0
    assert constants.PTYPE.ORPHANED.value == 0x13
    flags = constants.PFC.FIRST_FRAG | constants.PFC.LAST_FRAG
    assert flags.value == 3
    assert constants.PFC(3) == flags
    assert bindack.ResultEnum(2) is bindack.ResultEnum.PROVIDER_REJECTION
    assert bindnack.RejectReason(4) is (
        bindnack.RejectReason.PROTOCOL_VERSION_NOT_SUPPORTED
    )
