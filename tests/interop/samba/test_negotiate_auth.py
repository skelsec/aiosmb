"""Live SMB dialect, NTLM authentication, and signing observations."""

import pytest

from aiosmb.protocol.common import NegotiateDialects

from ._lab import logged_in


pytestmark = [pytest.mark.samba, pytest.mark.asyncio]


@pytest.mark.parametrize(
    "dialect",
    [
        NegotiateDialects.SMB202,
        NegotiateDialects.SMB210,
        NegotiateDialects.SMB300,
        NegotiateDialects.SMB302,
        NegotiateDialects.SMB311,
    ],
)
@pytest.mark.capability("protocol_probe")
async def test_live_protocol_probe_negotiates_declared_dialects(
    samba_profile, dialect
):
    if dialect.name not in samba_profile.dialects:
        pytest.skip(
            "Samba profile does not declare dialect {}".format(dialect.name)
        )

    connection = samba_profile.factory().get_connection()
    supported, signing_enabled, _, reply, error = await connection.protocol_test(
        [dialect]
    )

    assert error is None, "protocol probe failed with {}".format(
        type(error).__name__
    )
    assert supported is True
    assert signing_enabled is True
    assert reply.command.DialectRevision is dialect


@pytest.mark.capability("ntlm")
async def test_ntlm_login_selects_profile_dialect(
    samba_profile, record_property
):
    samba_profile.require_capability("ntlm")

    async with logged_in(samba_profile) as connection:
        record_property("samba_profile", samba_profile.name)
        record_property("negotiated_dialect", connection.selected_dialect.name)
        assert connection.login_ok is True
        assert connection.SessionId != 0
        assert connection.selected_dialect.name == samba_profile.dialect


@pytest.mark.capability("signing_observation")
async def test_signing_state_is_observable_after_login(
    samba_profile, record_property
):
    samba_profile.require_capability("signing_observation")

    async with logged_in(samba_profile) as connection:
        observations = connection.get_extra_info()
        record_property(
            "server_signing_enabled", observations["signing_enabled"]
        )
        record_property(
            "server_signing_required", observations["signing_required"]
        )
        record_property(
            "client_signing_active", connection.SigningKey is not None
        )

        assert observations["signing_enabled"] is True
        assert observations["signing_required"] is False
        assert connection.signing_required is True
        assert connection.SigningKey is not None
