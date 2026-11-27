"""Unauthenticated GOAD inventory, dialect, signing, and fingerprint probes."""

import pytest

from ._lab import CREDENTIAL_TIERS, EXAMPLE_PROFILE, load_profile


pytestmark = pytest.mark.windows


def test_committed_goad_manifest_is_secret_free_and_complete() -> None:
    profile = load_profile(EXAMPLE_PROFILE)

    assert profile.active is False
    assert profile.lab_kind == "vulnerable_integration"
    assert tuple(profile.credential_tiers) == CREDENTIAL_TIERS
    assert {
        target.id: (
            target.host,
            target.expected["role"],
            target.expected["server_label"],
        )
        for target in profile.targets.values()
    } == {
        "kingslanding": (
            "192.168.56.10",
            "domain_controller",
            "Windows Server 2019",
        ),
        "winterfell": (
            "192.168.56.11",
            "domain_controller",
            "Windows Server 2019",
        ),
        "meereen": (
            "192.168.56.12",
            "domain_controller",
            "Windows Server 2016",
        ),
        "castelblack": (
            "192.168.56.22",
            "member_server",
            "Windows Server 2019",
        ),
        "braavos": (
            "192.168.56.23",
            "member_server",
            "Windows Server 2016",
        ),
    }


def test_runtime_identity_role_and_build_match_inventory(
    windows_target, windows_metadata, record_property
) -> None:
    failed = [
        name
        for name, matched in windows_metadata["expectations"].items()
        if not matched
    ]
    record_property("windows_target", windows_target.id)
    record_property("runtime_role", windows_metadata["runtime_role"])
    record_property(
        "runtime_server_label", windows_metadata["runtime_server_label"]
    )
    record_property(
        "runtime_capabilities",
        ",".join(windows_metadata["capabilities"]),
    )

    assert not failed, "runtime inventory mismatches: {}".format(
        ", ".join(failed)
    )


def test_dialect_and_signing_probe_matches_target_metadata(
    windows_target, windows_metadata
) -> None:
    observed = {
        item["name"]: item
        for item in windows_metadata["dialects"]
        if item.get("supported") is True
    }
    expected_dialects = set(windows_target.expected["modern_dialects"])

    assert expected_dialects <= set(observed)
    for dialect in expected_dialects:
        assert observed[dialect]["signing_enabled"] is True
        assert observed[dialect]["signing_required"] is (
            windows_target.expected["signing_required"] is True
        )


def test_ntlm_fingerprint_exposes_expected_machine_metadata(
    windows_target, windows_metadata
) -> None:
    fingerprint = windows_metadata["fingerprint"]

    assert "error_type" not in fingerprint
    assert fingerprint["computername"].upper() == str(
        windows_target.expected["computer_name"]
    ).upper()
    assert fingerprint["dnscomputername"].lower() == str(
        windows_target.expected["fqdn"]
    ).lower()
    assert fingerprint["os_build"] == windows_target.expected["build"]


def test_smb1_only_target_is_probe_only(windows_metadata) -> None:
    supported = {
        item["name"]
        for item in windows_metadata["dialects"]
        if item.get("supported") is True
    }
    modern = supported & {"SMB202", "SMB210", "SMB300", "SMB302", "SMB311"}

    if modern:
        assert windows_metadata["probe_only"] is False
    else:
        assert windows_metadata["probe_only"] is True
