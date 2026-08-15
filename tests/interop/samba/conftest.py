"""Safety fixtures for explicitly enabled Samba interoperability tests."""

import pytest

from ._lab import load_profile, require_reachable


@pytest.fixture(scope="session")
def samba_profile(request):
    if not request.config.getoption("--run-samba"):
        pytest.skip("requires explicit --run-samba opt-in")
    profile = load_profile()
    require_reachable(profile)
    return profile


@pytest.fixture(scope="session")
def samba_destructive_profile(samba_profile):
    if not samba_profile.disposable:
        pytest.skip("Samba target is not declared disposable")
    if not samba_profile.allow_destructive:
        pytest.skip("Samba profile does not allow destructive tests")
    return samba_profile
