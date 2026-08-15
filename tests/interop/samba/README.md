# Samba interoperability

This directory contains the opt-in live interoperability suite and a disposable
Samba target. No container, live profile, port, or credential is required for
collection or for the default test suite.

## Reproducible target

The lab deliberately pins both layers that influence the server:

- `debian:12.11-slim` is pinned by OCI index digest
  `sha256:b1a741487078b369e78119849663d7f1a5341ef2768798f7b7406c4240f86aef`.
- APT reads the immutable Debian snapshot `20250811T000000Z`. Repository
  metadata remains Debian-signed even though the snapshot URL uses HTTP.
- `samba`, `samba-common-bin`, `samba-vfs-modules`, and `smbclient` are
  explicitly pinned to Debian package `2:4.17.12+dfsg-0+deb12u2`; the snapshot
  fixes their dependency closure.

The expected runtime report is `Version 4.17.12-Debian`. Capture the exact
values from a running target with:

```console
docker compose -f tests/interop/samba/compose.yml exec -T samba smbd --version
docker compose -f tests/interop/samba/compose.yml exec -T samba \
  dpkg-query -W samba
```

The server permits SMB 2.0.2 through SMB 3.1.1, NTLMv2 authentication, signing
negotiation, SRVSVC over `IPC$`, and a writable `interop` share. The container
filesystem is disposable and Compose declares no persistent volume.

## Test-only credentials

The committed defaults are intentionally non-secret and must never be reused:

- workgroup: `AIOSMB`
- username: `aiosmbtest`
- password: `Aiosmb-Test-Only-1!`
- endpoint: `127.0.0.1:1445`

Override the client and container together with
`AIOSMB_SAMBA_USERNAME`, `AIOSMB_SAMBA_PASSWORD`,
`AIOSMB_SAMBA_WORKGROUP`, `AIOSMB_SAMBA_SHARE`, and
`AIOSMB_SAMBA_PORT`. `AIOSMB_SAMBA_HOST` changes only the client profile and is
useful for remote disposable targets. Credential values are not printed by the
runner or included in assertion messages.

## Run the managed lab

From the repository root:

```console
tests/interop/samba/run-lab.sh
```

The runner builds the image, waits for Compose health, prints the Samba runtime
and package versions, runs the marked suite, and tears the project down with
volumes and orphans removed on success, failure, interruption, or build/start
failure. Extra pytest arguments are accepted, for example:

```console
tests/interop/samba/run-lab.sh -k negotiate -vv
```

To drive the steps manually, export
`AIOSMB_SAMBA_PROFILE=tests/interop/samba/profile.example.yml`, start Compose,
wait until it is healthy, and run:

```console
python3 -m pytest tests/interop/samba \
  --run-samba --run-destructive --run-slow \
  --capability protocol_probe --capability ntlm \
  --capability signing_observation --capability directory_crud \
  --capability file_crud --capability large_transfer \
  --capability concurrency --capability srvsvc \
  --capability security_descriptor
```

Always finish a manual run with:

```console
docker compose -f tests/interop/samba/compose.yml \
  down --volumes --remove-orphans
```

## External profiles and safety gates

Copy `profile.example.yml` to the ignored `profile.local.yml`, or point
`AIOSMB_SAMBA_PROFILE` at another YAML file. Tests skip unless all of the
following hold:

1. the test has its `samba` marker and pytest receives `--run-samba`;
2. a profile is explicitly available;
3. the profile endpoint accepts a TCP connection;
4. destructive tests also receive `--run-destructive`, and the profile declares
   both `disposable: true` and `allow_destructive: true`;
5. slow or capability-marked tests receive their corresponding opt-ins.

Reachability, missing capabilities, unsupported external dialects, container
runtime failures, and target-policy incompatibilities are infrastructure skips,
not aiosmb defects.

## Coverage and defect reporting

The suite separately covers live per-dialect probes, SMB 3.1.1 NTLM login,
signing observations, SRVSVC share enumeration, file/directory CRUD, a
multi-megabyte digest-checked transfer, concurrent authenticated sessions, and
file security-descriptor decoding.

Only behavior confirmed against the pinned lab as an aiosmb production defect
may use IDs `KF-0700` through `KF-0749`. Such a test must be a strict xfail and
must have a sanitized entry in `known_failures.report.yml`. Do not classify
Docker, host networking, profile, Samba policy, or optional RPC incompatibility
as a product defect.
