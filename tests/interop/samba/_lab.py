"""Secret-safe profile loading and connection helpers for the Samba lab."""

import os
import socket
import sys
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
import yaml


LAB_DIRECTORY = Path(__file__).resolve().parent
DEFAULT_PROFILE = LAB_DIRECTORY / "profile.local.yml"


def _required(mapping, key, section):
    value = mapping.get(key)
    if value in (None, ""):
        raise pytest.UsageError(
            "Samba profile field {}.{} is required".format(section, key)
        )
    return value


class SambaLabProfile:
    """Resolved live target settings without a credential-bearing repr."""

    def __init__(self, path, document):
        if document.get("schema_version") != 1:
            raise pytest.UsageError("unsupported Samba profile schema")

        target = document.get("target") or {}
        authentication = document.get("authentication") or {}
        overrides = document.get("environment_overrides") or {}
        safety = document.get("safety") or {}

        self.path = path
        self.name = str(_required(document, "name", "root"))
        self.host = self._environment_value(
            overrides, "host", _required(target, "host", "target")
        )
        port = self._environment_value(
            overrides, "port", _required(target, "port", "target")
        )
        try:
            self.port = int(port)
        except (TypeError, ValueError):
            raise pytest.UsageError("Samba profile port must be an integer")

        self.workgroup = str(
            self._environment_value(
                overrides,
                "workgroup",
                _required(target, "workgroup", "target"),
            )
        )
        self.share = str(
            self._environment_value(
                overrides, "share", _required(target, "share", "target")
            )
        )
        self.dialect = str(target.get("dialect", "SMB311")).upper()
        self.dialects = {
            str(value).upper() for value in target.get("dialects", [])
        }

        if authentication.get("mechanism") != "ntlm-password":
            raise pytest.UsageError(
                "Samba profile must use the ntlm-password mechanism"
            )
        username_environment = _required(
            authentication, "username_environment", "authentication"
        )
        password_environment = _required(
            authentication, "password_environment", "authentication"
        )
        self.username = os.environ.get(
            str(username_environment),
            str(
                _required(
                    authentication,
                    "test_only_default_username",
                    "authentication",
                )
            ),
        )
        self.password = os.environ.get(
            str(password_environment),
            str(
                _required(
                    authentication,
                    "test_only_default_password",
                    "authentication",
                )
            ),
        )
        self.disposable = safety.get("disposable") is True
        self.allow_destructive = safety.get("allow_destructive") is True
        self.capabilities = {
            str(value) for value in document.get("capabilities", [])
        }
        self.expected = document.get("expected") or {}

    @staticmethod
    def _environment_value(overrides, name, default):
        environment_name = overrides.get(name)
        if environment_name:
            return os.environ.get(str(environment_name), default)
        return default

    def factory(self, dialect=None):
        if sys.version_info < (3, 9):
            pytest.skip("blocked by KF-0107")
        from aiosmb.commons.connection.factory import SMBConnectionFactory

        return SMBConnectionFactory.from_components(
            self.host,
            self.username,
            self.password,
            secrettype="password",
            domain=self.workgroup,
            port=self.port,
            dialect=(dialect or self.dialect).lower(),
            authproto="ntlm",
        )

    def remote_path(self, *parts):
        suffix = "\\".join(part.strip("\\") for part in parts if part)
        if suffix:
            return "\\{}\\{}".format(self.share, suffix)
        return "\\{}".format(self.share)

    def unc_path(self, *parts):
        suffix = "\\".join(part.strip("\\") for part in parts if part)
        if suffix:
            return "\\\\{}\\{}\\{}".format(self.host, self.share, suffix)
        return "\\\\{}\\{}".format(self.host, self.share)

    def require_capability(self, name):
        if name not in self.capabilities:
            pytest.skip(
                "Samba profile does not declare capability {!r}".format(name)
            )


def load_profile():
    configured_path = os.environ.get("AIOSMB_SAMBA_PROFILE")
    path = Path(configured_path).expanduser() if configured_path else DEFAULT_PROFILE
    if not path.is_file():
        pytest.skip(
            "no Samba profile provided; set AIOSMB_SAMBA_PROFILE or create "
            "tests/interop/samba/profile.local.yml"
        )
    with path.open("r", encoding="utf-8") as profile_file:
        document = yaml.safe_load(profile_file)
    if not isinstance(document, dict):
        raise pytest.UsageError("Samba profile root must be a mapping")
    return SambaLabProfile(path, document)


def require_reachable(profile):
    try:
        connection = socket.create_connection(
            (profile.host, profile.port), timeout=2.0
        )
    except OSError:
        pytest.skip(
            "Samba profile target is not reachable at {}:{}".format(
                profile.host, profile.port
            )
        )
    else:
        connection.close()


@asynccontextmanager
async def logged_in(profile, dialect=None):
    connection = profile.factory(dialect=dialect).get_connection()
    try:
        success, error = await connection.login()
        if error is not None:
            raise AssertionError(
                "NTLM login failed with {}".format(type(error).__name__)
            ) from error
        if success is not True:
            raise AssertionError("NTLM login did not report success")
        yield connection
    finally:
        await connection.terminate()
