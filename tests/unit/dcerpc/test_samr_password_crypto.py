"""Known-answer tests for the deterministic SAMR password primitives."""

import pytest

from aiosmb.dcerpc.v5 import samr


pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "password, expected",
    [
        ("", "aad3b435b51404eeaad3b435b51404ee"),
        ("Password", "e52cac67419a9a224a3b108f3fa6cb6d"),
        ("password", "e52cac67419a9a224a3b108f3fa6cb6d"),
    ],
)
def test_lmowfv1_known_answer_vectors(password, expected):
    assert samr.LMOWFv1(password) == bytes.fromhex(expected)


def test_lmowfv1_uppercases_and_truncates_to_fourteen_characters():
    assert samr.LMOWFv1("abcdefghijklmn-extra") == samr.LMOWFv1(
        "ABCDEFGHIJKLMN"
    )


@pytest.mark.parametrize(
    "password, expected",
    [
        ("", "31d6cfe0d16ae931b73c59d7e0c089c0"),
        ("Password", "a4f49c406510bdcab6824ee7c30fd852"),
        ("password", "8846f7eaee8fb117ad06bdd830b7586c"),
        ("pässwörd", "0553152250ac01adb4213cb9938663e4"),
    ],
)
def test_ntowfv1_known_answer_vectors(password, expected):
    assert samr.NTOWFv1(password) == bytes.fromhex(expected)


def test_ntowfv1_accepts_preencoded_utf16le_bytes():
    password = "Password"

    assert samr.NTOWFv1(password.encode("utf-16-le")) == samr.NTOWFv1(password)


@pytest.mark.parametrize(
    "input_key, expected",
    [
        ("0123456789abcd", "0090d0ac784cae9a"),
        ("00010203040506", "000040403020140c"),
        ("ffffffffffffff", "fefefefefefefefe"),
    ],
)
def test_transform_key_expands_seven_bytes_for_des(input_key, expected):
    transformed = samr.transform_key(bytes.fromhex(input_key))

    assert transformed == bytes.fromhex(expected)
    assert len(transformed) == 8
    assert all((byte & 1) == 0 for byte in transformed)


def test_sam_encrypt_ntlm_hash_known_answer_and_round_trip():
    plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
    key = bytes.fromhex("0123456789abcdeffedcba9876543210")
    ciphertext = bytes.fromhex("29f4fd5176573a9d3eed4c8b2b71ecb8")

    assert samr.SamEncryptNTLMHash(plaintext, key) == ciphertext
    assert samr.SamDecryptNTLMHash(ciphertext, key) == plaintext


def test_sam_hash_crypto_uses_the_first_fourteen_key_bytes():
    plaintext = bytes.fromhex("ffeeddccbbaa99887766554433221100")
    first_fourteen = bytes.fromhex("00112233445566778899aabbccdd")

    first = samr.SamEncryptNTLMHash(plaintext, first_fourteen + b"\x00\x00")
    second = samr.SamEncryptNTLMHash(plaintext, first_fourteen + b"\xff\xff")

    assert first == second


def test_encrypted_owf_password_is_exactly_sixteen_wire_bytes():
    value = samr.ENCRYPTED_LM_OWF_PASSWORD()
    value["Data"] = bytes(range(16))

    wire = value.getData()

    assert wire == bytes(range(16))
    assert samr.ENCRYPTED_NT_OWF_PASSWORD(wire)["Data"] == bytes(range(16))
    assert value.getAlignment() == 1


def test_sampr_user_password_buffer_and_length_round_trip():
    password = samr.SAMPR_USER_PASSWORD()
    password["Buffer"] = b"A" * 512
    password["Length"] = 18

    wire = password.getData()

    assert len(wire) == 516
    assert wire[:512] == b"A" * 512
    assert wire[-4:] == bytes.fromhex("12000000")
    parsed = samr.SAMPR_USER_PASSWORD(wire)
    assert parsed["Buffer"] == b"A" * 512
    assert parsed["Length"] == 18


@pytest.mark.parametrize(
    "password_type, size",
    [
        (samr.SAMPR_ENCRYPTED_USER_PASSWORD, 516),
        (samr.SAMPR_ENCRYPTED_USER_PASSWORD_NEW, 522),
    ],
)
def test_sampr_encrypted_password_blob_fixed_width(password_type, size):
    value = password_type()
    value["Buffer"] = b"\xA5" * size

    wire = value.getData()

    assert wire == b"\xA5" * size
    assert password_type(wire)["Buffer"] == b"\xA5" * size
    assert value.getAlignment() == 1
