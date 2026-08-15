"""Secret-safe helpers for the opt-in Windows GOAD interoperability lab."""

import asyncio
import ipaddress
import logging
import os
import re
import socket
import sys
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set

import pytest
import yaml

from aiosmb.protocol.common import NegotiateDialects


LAB_DIRECTORY = Path(__file__).resolve().parent
DEFAULT_PROFILE = LAB_DIRECTORY / "profile.local.yml"
EXAMPLE_PROFILE = LAB_DIRECTORY / "goad.example.yml"
PROFILE_ENVIRONMENT = "AIOSMB_WINDOWS_PROFILE"
TARGETS_ENVIRONMENT = "AIOSMB_WINDOWS_TARGETS"
CREDENTIAL_TIERS = (
    "user",
    "admin",
    "domain_admin",
    "machine",
    "certificate",
)
MODERN_DIALECTS = (
    NegotiateDialects.SMB202,
    NegotiateDialects.SMB210,
    NegotiateDialects.SMB300,
    NegotiateDialects.SMB302,
    NegotiateDialects.SMB311,
)
PROBE_DIALECTS = (NegotiateDialects.WILDCARD,) + MODERN_DIALECTS
BUILD_LABELS = {
    14393: "Windows Server 2016",
    17763: "Windows Server 2019",
    20348: "Windows Server 2022",
    26100: "Windows Server 2025",
}
CAPABILITY_DENIAL_TOKENS = (
    "ACCESS_DENIED",
    "PRIVILEGE_NOT_HELD",
    "PIPE_NOT_AVAILABLE",
    "OBJECT_NAME_NOT_FOUND",
    "OBJECT_PATH_NOT_FOUND",
    "NOT_SUPPORTED",
    "BAD_NETWORK_NAME",
    "SERVICE_DISABLED",
)
_SENSITIVE_LITERAL_KEYS = {
    "certificate",
    "username",
    "principal",
    "password",
    "secret",
    "private_key",
    "pfx",
}
_URL_USERINFO = re.compile(r"(?i)([a-z][a-z0-9+.-]*://)[^/@\s]+@")
_NAMED_SECRET = re.compile(
    r"(?i)\b(username|principal|password|passwd|secret|token)\s*"
    r"([:=])\s*([^\s,;]+)"
)


class MissingCredential(Exception):
    """Names missing environment variables without retaining their values."""

    def __init__(self, tier: str, environment_names: Sequence[str]) -> None:
        self.tier = tier
        self.environment_names = tuple(environment_names)
        super().__init__(
            "{} credential tier is missing environment variables: {}".format(
                tier, ", ".join(self.environment_names)
            )
        )


class Credential:
    """Resolved credentials whose representation is always redacted."""

    def __init__(self, tier: str, mechanism: str, values: Mapping[str, str]):
        self.tier = tier
        self.mechanism = mechanism
        self.values = dict(values)

    def __repr__(self) -> str:
        return "<Credential tier={!r} redacted>".format(self.tier)

    __str__ = __repr__


def _required(mapping: Mapping[str, Any], key: str, section: str) -> Any:
    value = mapping.get(key)
    if value in (None, ""):
        raise pytest.UsageError(
            "Windows profile field {}.{} is required".format(section, key)
        )
    return value


def _mapping(value: Any, section: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise pytest.UsageError(
            "Windows profile section {} must be a mapping".format(section)
        )
    return value


def _assert_no_credential_literals(value: Any, path: str = "root") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key)
            is_certificate_tier = (
                path == "root.credential_tiers"
                and key_text.lower() == "certificate"
            )
            if (
                key_text.lower() in _SENSITIVE_LITERAL_KEYS
                and not is_certificate_tier
            ):
                raise pytest.UsageError(
                    "credential literal field {}.{} is forbidden; use an "
                    "environment-variable name".format(path, key_text)
                )
            _assert_no_credential_literals(child, "{}.{}".format(path, key_text))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _assert_no_credential_literals(
                child, "{}[{}]".format(path, index)
            )


class CredentialTierSpec:
    def __init__(self, name: str, document: Mapping[str, Any]) -> None:
        self.name = name
        self.mechanism = str(
            _required(document, "mechanism", "credential_tiers.{}".format(name))
        )
        if self.mechanism == "ntlm-password":
            fields = ("username_environment", "password_environment")
        elif self.mechanism == "kerberos-pfx":
            fields = (
                "principal_environment",
                "pfx_environment",
                "pfx_password_environment",
            )
        else:
            raise pytest.UsageError(
                "unsupported credential mechanism {!r} for tier {!r}".format(
                    self.mechanism, name
                )
            )
        self.environments = {
            field: str(
                _required(
                    document,
                    field,
                    "credential_tiers.{}".format(name),
                )
            )
            for field in fields
        }

    @property
    def environment_names(self) -> Sequence[str]:
        return tuple(self.environments.values())

    def resolve(self) -> Credential:
        values: Dict[str, str] = {}
        missing: List[str] = []
        for field, environment_name in self.environments.items():
            value = os.environ.get(environment_name)
            if value in (None, ""):
                missing.append(environment_name)
            else:
                values[field] = value
        if missing:
            raise MissingCredential(self.name, missing)
        return Credential(self.name, self.mechanism, values)


class WindowsTarget:
    def __init__(self, profile: "WindowsLabProfile", document: Mapping[str, Any]):
        self.profile = profile
        self.id = str(_required(document, "id", "targets[]"))
        self.host = str(_required(document, "host", "targets.{}".format(self.id)))
        try:
            ipaddress.ip_address(self.host)
        except ValueError:
            raise pytest.UsageError(
                "Windows target {!r} host must be an IP address".format(self.id)
            )
        self.port = int(document.get("port", 445))
        self.timeout = float(document.get("timeout", 5.0))
        self.preferred_dialect = str(
            document.get("preferred_dialect", "SMB311")
        ).upper()
        self.expected = dict(
            _mapping(
                _required(document, "expected", "targets.{}".format(self.id)),
                "targets.{}.expected".format(self.id),
            )
        )
        self.dc_host = str(document.get("dc_host", self.host))
        self.capabilities: Set[str] = {
            str(item) for item in document.get("capabilities", ())
        }
        self.safe_reads: List[Mapping[str, Any]] = [
            _mapping(item, "targets.{}.safe_reads[]".format(self.id))
            for item in document.get("safe_reads", ())
        ]
        self.destructive = dict(
            _mapping(
                document.get("destructive", {}),
                "targets.{}.destructive".format(self.id),
            )
        )

    def __repr__(self) -> str:
        return "<WindowsTarget id={!r} host={!r}>".format(self.id, self.host)

    def require_declared_capability(self, capability: str) -> None:
        if capability not in self.capabilities:
            pytest.skip(
                "target {!r} does not declare capability {!r}".format(
                    self.id, capability
                )
            )

    def credential(self, tier: str) -> Credential:
        if not self.profile.active:
            pytest.skip(
                "authenticated Windows tests require an active ignored "
                "profile.local.yml"
            )
        try:
            spec = self.profile.credential_tiers[tier]
        except KeyError:
            raise pytest.UsageError(
                "unknown Windows credential tier {!r}".format(tier)
            )
        try:
            return spec.resolve()
        except MissingCredential as error:
            pytest.skip(str(error))

    def connection_factory(self, tier: str) -> "SMBConnectionFactory":
        if sys.version_info < (3, 9):
            pytest.skip("blocked by KF-0107")
        from aiosmb.commons.connection.factory import SMBConnectionFactory

        credential = self.credential(tier)
        domain = str(self.expected["dns_domain"])
        if credential.mechanism == "ntlm-password":
            return SMBConnectionFactory.from_components(
                self.host,
                credential.values["username_environment"],
                credential.values["password_environment"],
                secrettype="password",
                domain=str(self.expected["netbios_domain"]),
                port=self.port,
                dialect=self.preferred_dialect.lower(),
                authproto="ntlm",
            )
        from asyauth.common.constants import asyauthSecret
        from asyauth.common.credentials.kerberos import KerberosCredential

        from aiosmb.commons.connection.target import (
            SMBConnectionDialect,
            SMBTarget,
        )

        smb_target = SMBTarget(
            ip=self.host,
            port=self.port,
            hostname=str(self.expected["fqdn"]),
            dc_ip=self.dc_host,
            domain=domain,
        )
        smb_target.update_dialect(
            SMBConnectionDialect(self.preferred_dialect)
        )
        kerberos = KerberosCredential(
            credential.values["pfx_password_environment"],
            credential.values["principal_environment"],
            domain,
            asyauthSecret.PFX,
            target=smb_target,
            etypes=[23, 17, 18],
            keydata=credential.values["pfx_environment"],
        )
        return SMBConnectionFactory(kerberos, smb_target)

    def remote_path(self, share: str, path: str = "") -> str:
        suffix = path.strip("\\/")
        if suffix:
            return "\\{}\\{}".format(share, suffix.replace("/", "\\"))
        return "\\{}".format(share)

    def unc_path(self, share: str, path: str = "") -> str:
        suffix = path.strip("\\/")
        if suffix:
            return "\\\\{}\\{}\\{}".format(
                self.host, share, suffix.replace("/", "\\")
            )
        return "\\\\{}\\{}".format(self.host, share)


class WindowsLabProfile:
    def __init__(self, path: Path, document: Mapping[str, Any]) -> None:
        if document.get("schema_version") != 1:
            raise pytest.UsageError("unsupported Windows profile schema")
        _assert_no_credential_literals(document)
        self.path = path
        self.name = str(_required(document, "name", "root"))
        self.active = document.get("active") is True
        self.lab_kind = str(_required(document, "lab_kind", "root"))
        if self.lab_kind != "vulnerable_integration":
            raise pytest.UsageError(
                "Windows lab_kind must be 'vulnerable_integration'"
            )

        tiers_document = _mapping(
            _required(document, "credential_tiers", "root"),
            "credential_tiers",
        )
        missing_tiers = set(CREDENTIAL_TIERS) - set(tiers_document)
        if missing_tiers:
            raise pytest.UsageError(
                "Windows profile is missing credential tiers: {}".format(
                    ", ".join(sorted(missing_tiers))
                )
            )
        self.credential_tiers = {
            name: CredentialTierSpec(
                name,
                _mapping(
                    tiers_document[name],
                    "credential_tiers.{}".format(name),
                ),
            )
            for name in CREDENTIAL_TIERS
        }

        self.probe_ports = {
            str(name): int(port)
            for name, port in _mapping(
                document.get(
                    "probe_ports",
                    {"endpoint_mapper": 135, "directory_service": 389, "smb": 445},
                ),
                "probe_ports",
            ).items()
        }
        safety = _mapping(document.get("safety", {}), "safety")
        self.allow_destructive = safety.get("allow_destructive") is True
        self.destructive_allowlist = {
            str(item) for item in safety.get("destructive_allowlist", ())
        }
        self.snapshot_environment = str(
            safety.get(
                "snapshot_environment", "AIOSMB_WINDOWS_SNAPSHOT_CHECKPOINT"
            )
        )

        target_documents = document.get("targets")
        if not isinstance(target_documents, list) or not target_documents:
            raise pytest.UsageError(
                "Windows profile targets must be a non-empty list"
            )
        targets = [WindowsTarget(self, _mapping(item, "targets[]")) for item in target_documents]
        target_ids = [target.id for target in targets]
        if len(set(target_ids)) != len(target_ids):
            raise pytest.UsageError("Windows profile target ids must be unique")
        self.targets = {target.id: target for target in targets}

    def selected_targets(self) -> List[WindowsTarget]:
        configured = os.environ.get(TARGETS_ENVIRONMENT, "").strip()
        if not configured:
            return list(self.targets.values())
        selected_ids = [item.strip() for item in configured.split(",") if item.strip()]
        unknown = set(selected_ids) - set(self.targets)
        if unknown:
            raise pytest.UsageError(
                "unknown Windows target ids: {}".format(
                    ", ".join(sorted(unknown))
                )
            )
        return [self.targets[target_id] for target_id in selected_ids]

    def sensitive_environment_names(self) -> Set[str]:
        names: Set[str] = set()
        for tier in self.credential_tiers.values():
            names.update(tier.environment_names)
        return names


def configured_profile_path() -> Path:
    configured = os.environ.get(PROFILE_ENVIRONMENT)
    return Path(configured).expanduser() if configured else DEFAULT_PROFILE


def load_profile(path: Optional[Path] = None) -> WindowsLabProfile:
    resolved = path or configured_profile_path()
    if not resolved.is_file():
        pytest.skip(
            "no active Windows profile; set {} or create {}".format(
                PROFILE_ENVIRONMENT, DEFAULT_PROFILE
            )
        )
    with resolved.open("r", encoding="utf-8") as profile_file:
        document = yaml.safe_load(profile_file)
    if not isinstance(document, dict):
        raise pytest.UsageError("Windows profile root must be a mapping")
    return WindowsLabProfile(resolved, document)


def collection_target_ids() -> List[Optional[str]]:
    path = configured_profile_path()
    if not path.is_file():
        return [None]
    return [target.id for target in load_profile(path).selected_targets()]


@contextmanager
def quiet_aiosmb() -> Iterable[None]:
    logger = logging.getLogger("aiosmb")
    previous_disabled = logger.disabled
    logger.disabled = True
    try:
        yield
    finally:
        logger.disabled = previous_disabled


async def _probe_port(host: str, port: int, timeout: float) -> bool:
    loop = asyncio.get_running_loop()
    try:
        connection = await asyncio.wait_for(
            loop.run_in_executor(
                None, lambda: socket.create_connection((host, port), timeout)
            ),
            timeout=timeout + 0.5,
        )
    except (OSError, asyncio.TimeoutError):
        return False
    connection.close()
    return True


def _dummy_factory(target: WindowsTarget) -> "SMBConnectionFactory":
    if sys.version_info < (3, 9):
        pytest.skip("blocked by KF-0107")
    from aiosmb.commons.connection.factory import SMBConnectionFactory

    factory = SMBConnectionFactory.create_dummy()
    factory.target.port = target.port
    factory.target.timeout = target.timeout
    return factory


async def _probe_dialect(
    target: WindowsTarget,
    dialect: NegotiateDialects,
) -> Mapping[str, Any]:
    connection = _dummy_factory(target).create_connection_newtarget(target.host)
    try:
        supported, signing_enabled, signing_required, _, error = await asyncio.wait_for(
            connection.protocol_test([dialect]),
            timeout=target.timeout,
        )
    except Exception as error:
        return {
            "name": dialect.name,
            "supported": False,
            "error_type": type(error).__name__,
        }
    if error is not None:
        return {
            "name": dialect.name,
            "supported": False,
            "error_type": type(error).__name__,
        }
    return {
        "name": dialect.name,
        "supported": supported is True,
        "signing_enabled": signing_enabled,
        "signing_required": signing_required,
    }


def _fingerprint_dict(value: Any) -> Mapping[str, Any]:
    raw = value.to_dict()
    allowed = (
        "domainname",
        "computername",
        "dnscomputername",
        "dnsdomainname",
        "dnsforestname",
        "os_build",
        "os_guess",
        "os_major_version",
        "os_minor_version",
    )
    result: Dict[str, Any] = {}
    for key in allowed:
        item = raw.get(key)
        if item is None or isinstance(item, (bool, int, float, str)):
            result[key] = item
        else:
            result[key] = getattr(item, "name", str(item))
    return result


async def _probe_fingerprint(target: WindowsTarget) -> Mapping[str, Any]:
    connection = _dummy_factory(target).create_connection_newtarget(target.host)
    try:
        fingerprint, error = await asyncio.wait_for(
            connection.fake_login(), timeout=target.timeout
        )
    except Exception as error:
        return {"error_type": type(error).__name__}
    if error is not None:
        return {"error_type": type(error).__name__}
    if fingerprint is None:
        return {"error_type": "MissingFingerprint"}
    return _fingerprint_dict(fingerprint)


def _expectation_checks(
    target: WindowsTarget,
    metadata: Mapping[str, Any],
) -> Mapping[str, bool]:
    fingerprint = metadata["fingerprint"]
    expected = target.expected
    build = fingerprint.get("os_build")
    observed_role = metadata["runtime_role"]
    observed_label = BUILD_LABELS.get(build)
    return {
        "computer_name": str(fingerprint.get("computername", "")).upper()
        == str(expected["computer_name"]).upper(),
        "fqdn": str(fingerprint.get("dnscomputername", "")).lower()
        == str(expected["fqdn"]).lower(),
        "dns_domain": str(fingerprint.get("dnsdomainname", "")).lower()
        == str(expected["dns_domain"]).lower(),
        "netbios_domain": str(fingerprint.get("domainname", "")).upper()
        == str(expected["netbios_domain"]).upper(),
        "build": build == int(expected["build"]),
        "server_label": observed_label == str(expected["server_label"]),
        "role": observed_role == str(expected["role"]),
    }


async def discover_target(target: WindowsTarget) -> Mapping[str, Any]:
    reachability_values = await asyncio.gather(
        *(
            _probe_port(target.host, port, target.timeout)
            for port in target.profile.probe_ports.values()
        )
    )
    reachability = dict(zip(target.profile.probe_ports, reachability_values))
    metadata: Dict[str, Any] = {
        "target_id": target.id,
        "host": target.host,
        "reachability": reachability,
        "dialects": [],
        "fingerprint": {"error_type": "SMBUnreachable"},
        "capabilities": [],
    }
    capabilities: Set[str] = {
        "tcp_{}".format(port_name)
        for port_name, reachable in reachability.items()
        if reachable
    }
    if reachability.get("endpoint_mapper"):
        capabilities.add("rpc_endpoint_mapper")
    if reachability.get("directory_service"):
        capabilities.add("directory_service")
    if reachability.get("smb"):
        capabilities.add("smb_reachable")
        with quiet_aiosmb():
            for dialect in PROBE_DIALECTS:
                metadata["dialects"].append(
                    await _probe_dialect(target, dialect)
                )
            metadata["fingerprint"] = await _probe_fingerprint(target)

    supported = {
        item["name"]
        for item in metadata["dialects"]
        if item.get("supported") is True
    }
    modern = supported & {dialect.name for dialect in MODERN_DIALECTS}
    if "WILDCARD" in supported:
        capabilities.add("smb1_probe")
    if modern:
        capabilities.add("modern_smb")
    if any(name.startswith("SMB3") for name in modern):
        capabilities.add("smb3")
    if metadata["fingerprint"].get("computername"):
        capabilities.add("ntlm_fingerprint")
    if any(
        item.get("signing_enabled") is True for item in metadata["dialects"]
    ):
        capabilities.add("signing_enabled")
    if any(
        item.get("signing_required") is True for item in metadata["dialects"]
    ):
        capabilities.add("signing_required")

    metadata["probe_only"] = bool(supported) and not bool(modern)
    if metadata["probe_only"]:
        capabilities.add("probe_only")
    metadata["runtime_role"] = (
        "domain_controller"
        if "directory_service" in capabilities
        else "member_server"
    )
    build = metadata["fingerprint"].get("os_build")
    metadata["runtime_server_label"] = BUILD_LABELS.get(
        build, "unknown-build-{}".format(build)
    )
    metadata["capabilities"] = sorted(capabilities)
    metadata["expectations"] = _expectation_checks(target, metadata)
    metadata["all_expectations_met"] = all(metadata["expectations"].values())
    return metadata


async def discover_profile(
    profile: WindowsLabProfile,
) -> List[Mapping[str, Any]]:
    return list(
        await asyncio.gather(
            *(discover_target(target) for target in profile.selected_targets())
        )
    )


def require_runtime_capability(
    metadata: Mapping[str, Any], capability: str
) -> None:
    if capability not in set(metadata["capabilities"]):
        pytest.skip(
            "runtime discovery did not find capability {!r} on {!r}".format(
                capability, metadata["target_id"]
            )
        )


def _error_tokens(error: Exception) -> Set[str]:
    tokens = {type(error).__name__.upper()}
    for attribute in ("ntstatus", "status", "error_code", "errno"):
        value = getattr(error, attribute, None)
        if value is None:
            continue
        tokens.add(str(getattr(value, "name", value)).upper())
    return tokens


def capability_error(error: Optional[Exception], capability: str) -> None:
    if error is None:
        return
    tokens = _error_tokens(error)
    if any(
        denial in token
        for denial in CAPABILITY_DENIAL_TOKENS
        for token in tokens
    ):
        pytest.skip(
            "runtime capability {!r} is unavailable ({})".format(
                capability, type(error).__name__
            )
        )
    pytest.fail(
        "runtime capability {!r} failed with {}".format(
            capability, type(error).__name__
        ),
        pytrace=False,
    )


@asynccontextmanager
async def logged_in(
    target: WindowsTarget,
    tier: str,
    compression: bool = False,
    compression_algorithm=None,
):
    connection = None
    with quiet_aiosmb():
        try:
            factory = target.connection_factory(tier)
            connection = factory.get_connection()
            if compression:
                from aiosmb.protocol.compression import backend

                backend.require_available(compression_algorithm)
                connection.target.compression = True
                connection.CompressAllRequests = True
                if compression_algorithm is None:
                    connection.CompressionIds = list(backend.supported_algorithms())
                else:
                    connection.target.compression_algorithms = (
                        compression_algorithm,
                    )
                    connection.CompressionIds = [compression_algorithm]
            success, error = await asyncio.wait_for(
                connection.login(), timeout=target.timeout
            )
            if error is not None:
                pytest.fail(
                    "{} authentication failed with {}".format(
                        tier, type(error).__name__
                    ),
                    pytrace=False,
                )
            if success is not True:
                pytest.fail(
                    "{} authentication did not report success".format(tier),
                    pytrace=False,
                )
            yield connection
        finally:
            if connection is not None:
                try:
                    await asyncio.wait_for(
                        connection.terminate(), timeout=target.timeout
                    )
                except Exception:
                    pass


def require_destructive_safety(
    target: WindowsTarget, operation: str
) -> Mapping[str, Any]:
    profile = target.profile
    if not profile.active:
        pytest.skip("destructive tests require an active ignored profile")
    if not profile.allow_destructive:
        pytest.skip("profile does not allow destructive Windows tests")
    if target.id not in profile.destructive_allowlist:
        pytest.skip("target is not in the destructive allowlist")
    if target.destructive.get("disposable") is not True:
        pytest.skip("target is not declared disposable")
    operations = _mapping(
        target.destructive.get("operations", {}),
        "targets.{}.destructive.operations".format(target.id),
    )
    settings = operations.get(operation)
    if not isinstance(settings, dict):
        pytest.skip(
            "destructive operation {!r} is not configured".format(operation)
        )
    if settings.get("deterministic_cleanup") is not True:
        pytest.skip("destructive operation lacks deterministic cleanup")
    if not os.environ.get(profile.snapshot_environment):
        pytest.skip(
            "snapshot checkpoint environment variable {} is required".format(
                profile.snapshot_environment
            )
        )
    return settings


def sensitive_values(profile: WindowsLabProfile) -> List[str]:
    return [
        value
        for name in profile.sensitive_environment_names()
        for value in [os.environ.get(name)]
        if value
    ]


def sanitize_text(text: str, values: Iterable[str] = ()) -> str:
    sanitized = str(text)
    for value in sorted(set(values), key=len, reverse=True):
        if value:
            sanitized = sanitized.replace(value, "<redacted>")
    sanitized = _URL_USERINFO.sub(r"\1<redacted>@", sanitized)
    sanitized = _NAMED_SECRET.sub(
        lambda match: "{}{}<redacted>".format(match.group(1), match.group(2)),
        sanitized,
    )
    return sanitized
