# Windows GOAD interoperability

This directory is vulnerable-integration coverage for the standard five-host
GOAD lab. It is not a Windows or SMB conformance suite. Results describe this
specific lab and its intentionally weak policies.

The committed `goad.example.yml` is secret-free and inactive. It describes:

- `192.168.56.10` KINGSLANDING, domain controller, Server 2019 build 17763
- `192.168.56.11` WINTERFELL, domain controller, Server 2019 build 17763
- `192.168.56.12` MEEREEN, domain controller, Server 2016 build 14393
- `192.168.56.22` CASTELBLACK, member server, Server 2019 build 17763
- `192.168.56.23` BRAAVOS, member server, Server 2016 build 14393

The NTLM challenge verifies names, domains, and build numbers at runtime.
TCP/389 reachability is the runtime directory-service role signal. Test
selection uses discovered protocol/service capabilities and profile-declared
safe operations, never an OS-name guess. A target with only the legacy SMB1
probe remains probe-only and cannot reach an authenticated fixture.

## Safe defaults and profiles

Every test is marked `windows`; the default suite skips it unless
`--run-windows` is explicit. Privileged and destructive modules independently
require `--run-privileged` and `--run-destructive`.

For authenticated work, copy the public inventory to the ignored active path:

```shell
cp tests/interop/windows/goad.example.yml \
  tests/interop/windows/profile.local.yml
```

Set `active: true` only in that local file. `profile.local.yml` and
`profiles.local/` are gitignored repository-wide. Keep local changes limited to
safe read paths, capabilities actually observed, and safety declarations.

Credentials are resolved only from environment variables at fixture setup.
There are no defaults and no credential values in YAML, command arguments,
URLs, JUnit properties, or artifacts. The five tiers are:

- `user`: normal-user NTLM username/password
- `admin`: host-administrator NTLM username/password
- `domain_admin`: domain-administrator NTLM username/password
- `machine`: machine-account NTLM username/password
- `certificate`: Kerberos PKINIT principal, PFX, and PFX password

The exact environment-variable names are in `goad.example.yml`. Inject them
from a short-lived shell, CI secret store, or process supervisor. Do not put
values in chat, shell history, profile files, or pytest arguments. Unset all
tier variables after a run and rotate an identity immediately if output
handling or isolation fails.

## Discovery and test controller

Unauthenticated discovery is safe to run against the five inventory targets:

```shell
python3 tests/interop/windows/run.py discover
```

It performs TCP reachability, SMB dialect/signing probes, and an NTLM challenge
fingerprint. It does not resolve credential environment variables. Output goes
to the ignored `tests/interop/windows/artifacts.local/discovery.json`.

The controller can select a target and test group:

```shell
python3 tests/interop/windows/run.py test \
  --target kingslanding --group user
python3 tests/interop/windows/run.py test \
  --group privileged --privileged
python3 tests/interop/windows/run.py test \
  --group destructive --destructive
```

Test output is captured, credential environment values are redacted, and JUnit
plus stdout/stderr artifacts are written below
`tests/interop/windows/artifacts.local/`.
Failure diagnostics intentionally report operation and exception type, not
exception text, connection factories, URLs, or credential objects.

## Coverage groups

Normal-user tests are non-destructive: login, negotiated dialect/signing state,
SRVSVC share enumeration, SAMR domains and domain users, LSA primary-domain
identity, and bounded reads of files explicitly listed in `safe_reads`.
Committed targets have no safe file paths; a local profile must declare them:

```yaml
safe_reads:
  - share: explicitly-reviewed-share
    path: reviewed/read-only-file.txt
    max_bytes: 65536
    sha256: optional-lowercase-sha256
```

Privileged tests remain read-only and separately gated. They cover service
enumeration, selected Remote Registry values, and the DC NTDS path only when
runtime directory-service and declared registry capabilities are both present.
Machine and certificate identity checks authenticate without changing state.

Capability denials, unavailable RPC pipes, and disabled services are skips.
Unexpected transport/codec failures are sanitized failures and are candidates
for `known_failures.report.yml`. Only confirmed live aiosmb defects use the
reserved `KF-0800..KF-0899` range; environment failures never do.

## Destructive safety, snapshots, and cleanup

Destructive coverage is a skeleton until a local profile satisfies every
control:

1. The target is an isolated disposable clone, not a shared GOAD instance.
2. The root profile sets `allow_destructive: true`.
3. The target id appears in `destructive_allowlist`.
4. The target sets `disposable: true`.
5. The operation declares `deterministic_cleanup: true`, an allow-listed share,
   and an optional dedicated directory/prefix.
6. `AIOSMB_WINDOWS_SNAPSHOT_CHECKPOINT` identifies a verified pre-run snapshot.
7. `--run-windows --run-destructive` are both explicit.

The file round-trip uses a unique bounded name and deletes it in `finally`.
Cleanup failure fails the test. Process termination, host loss, and transport
failure can still bypass in-process cleanup, so snapshot restore is mandatory
before reusing a failed lab.

The compression round-trip has the same destructive controls and additionally
requires the optional native package, an SMB 3.1.1 Windows Server 2022/2025
target, and the declared `smb_compression` capability. It forces and verifies
LZNT1, LZ77, and LZ77+Huffman independently; LZ4 is also exercised on build
26100 or newer and skipped on older targets. Each case verifies outbound and
inbound transforms, exact data, incompressible fallback, and cleanup. The
committed GOAD Server 2016/2019 inventory does not claim this capability. A
private disposable profile can enable it with an allow-listed operation:

```yaml
capabilities:
  - authenticated_smb
  - smb_compression
destructive:
  disposable: true
  operations:
    compression_roundtrip:
      deterministic_cleanup: true
      share: dedicated-test-share
      directory: compression-tests
      credential_tier: user
```

Run it only with all three explicit gates:

```shell
python3 -m pip install ".[compression]"
python3 -m pytest tests/interop/windows/test_compression.py \
  --run-windows --run-destructive --capability compression
```

Create snapshots while all five guests are quiescent and label them with one
shared checkpoint identifier. Restore the complete trust topology together;
restoring only one domain member or controller can invalidate machine-account
passwords and AD replication state. After restore, rotate injected test
credentials, verify time synchronization and network isolation, rerun
unauthenticated discovery, and only then re-enable authenticated tiers.

Keep GOAD on a host-only/internal network. Block routes to production,
corporate DNS, the public internet, and non-lab RFC1918 ranges. Use a dedicated
runner with no production tickets, certificate stores, SSH agents, proxy
credentials, or mounted home directories. Destroy disposable clones after
destructive sessions.
