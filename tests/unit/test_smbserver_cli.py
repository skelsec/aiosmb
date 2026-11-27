import logging

import pytest

from aiosmb.examples import smbserver


pytestmark = pytest.mark.unit


def test_collect_shares_supports_writable_and_read_only(tmp_path) -> None:
    writable = tmp_path / "writable"
    readonly = tmp_path / "readonly"

    shares = smbserver.collect_shares(
        ["Data={}".format(writable)],
        ["Public={}".format(readonly)],
    )

    assert shares["Data"].root == writable
    assert shares["Data"].read_only is False
    assert shares["Public"].root == readonly
    assert shares["Public"].read_only is True


@pytest.mark.parametrize(
    "writable,readonly,message",
    [
        ([], [], "configure at least one"),
        (["missing-separator"], [], "NAME=PATH"),
        (["Data=/tmp/a"], ["data=/tmp/b"], "more than once"),
    ],
)
def test_collect_shares_rejects_invalid_definitions(
    writable, readonly, message
) -> None:
    with pytest.raises(ValueError, match=message):
        smbserver.collect_shares(writable, readonly)


def test_settings_from_password_arguments(tmp_path) -> None:
    args = smbserver.build_parser().parse_args(
        [
            "--username",
            "alice",
            "--password",
            "secret",
            "--domain",
            "LAB",
            "--share",
            "Data={}".format(tmp_path),
            "--require-signing",
            "--server-name",
            "FILEHOST",
            "--server-comment",
            "Test server",
            "--disable-ess",
        ]
    )

    settings = smbserver.settings_from_args(args)

    assert settings.RequireSigning is True
    assert settings.ServerName == "FILEHOST"
    assert settings.ServerComment == "Test server"
    assert settings.shares["Data"].root == tmp_path
    assert settings.DisableESS is True
    assert settings.create_new_gssapi(object()).credential.disable_ess is True


def test_downgrade_ess_alias_enables_the_same_policy(tmp_path) -> None:
    args = smbserver.build_parser().parse_args(
        [
            "--username",
            "alice",
            "--password",
            "secret",
            "--share",
            "Data={}".format(tmp_path),
            "--downgrade-ess",
        ]
    )

    settings = smbserver.settings_from_args(args)

    assert settings.DisableESS is True


def test_settings_without_credentials_enable_anonymous_access(tmp_path) -> None:
    args = smbserver.build_parser().parse_args(
        [
            "--share",
            "Data={}".format(tmp_path),
        ]
    )

    settings = smbserver.settings_from_args(args)
    authenticator = settings.create_new_gssapi(object())

    assert authenticator.credential.is_guest is True
    assert settings.RequireSigning is False


@pytest.mark.parametrize(
    "verbosity,expected_level",
    [
        ([], logging.INFO),
        (["-v"], logging.DEBUG),
        (["-vv"], smbserver.TRACE_LEVEL),
    ],
)
def test_server_logging_verbosity_levels(
    tmp_path, verbosity, expected_level
) -> None:
    args = smbserver.build_parser().parse_args(
        verbosity + ["--share", "Data={}".format(tmp_path)]
    )

    settings = smbserver.settings_from_args(args)

    assert settings.log_level == expected_level


@pytest.mark.parametrize(
    "credentials,message",
    [
        (["--username", "alice"], "--username requires"),
        (["--password", "secret"], "requires --username"),
        (
            ["--require-signing"],
            "anonymous access cannot be combined",
        ),
    ],
)
def test_settings_rejects_incomplete_anonymous_configuration(
    tmp_path, credentials, message
) -> None:
    args = smbserver.build_parser().parse_args(
        credentials + ["--share", "Data={}".format(tmp_path)]
    )

    with pytest.raises(ValueError, match=message):
        smbserver.settings_from_args(args)


def test_settings_rejects_invalid_nt_hash(tmp_path) -> None:
    args = smbserver.build_parser().parse_args(
        [
            "--username",
            "alice",
            "--nt-hash",
            "not-a-hash",
            "--share",
            "Data={}".format(tmp_path),
        ]
    )

    with pytest.raises(ValueError, match="hexadecimal"):
        smbserver.settings_from_args(args)


def test_parser_rejects_out_of_range_port() -> None:
    parser = smbserver.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(
            [
                "--port",
                "70000",
                "--username",
                "alice",
                "--password",
                "secret",
                "--share",
                "Data=/tmp",
            ]
        )


@pytest.mark.asyncio
async def test_amain_starts_server_with_configured_target(
    tmp_path, monkeypatch
) -> None:
    captured = {}

    def fake_target(host, port, protocol):
        captured["target"] = (host, port, protocol)
        return captured["target"]

    class FakeServer:
        def __init__(self, target, settings):
            captured["server_target"] = target
            captured["settings"] = settings

        async def run(self):
            async def completed():
                return None

            return completed(), None

    monkeypatch.setattr(smbserver, "UniTarget", fake_target)
    monkeypatch.setattr(smbserver, "SMBServer", FakeServer)
    args = smbserver.build_parser().parse_args(
        [
            "--host",
            "127.0.0.1",
            "--port",
            "1445",
            "--username",
            "alice",
            "--password",
            "secret",
            "--share",
            "Data={}".format(tmp_path),
        ]
    )

    await smbserver.amain(args)

    assert captured["target"][:2] == ("127.0.0.1", 1445)
    assert captured["server_target"] == captured["target"]
    assert "Data" in captured["settings"].shares
