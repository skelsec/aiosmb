# aiosmb test suite

The root `tests/` tree is the canonical pytest suite. The historical scripts
under `aiosmb/tests/` remain in place as source material and are not collected
by default.

## One-command runner

Use the executable at the repository root. It creates an isolated virtualenv,
installs the package and test dependencies, runs the requested tier, tears down
managed Docker infrastructure, and removes the virtualenv even after failure
or Ctrl-C:

```bash
./test.sh                         # baseline unit/fake-peer/component suite
./test.sh full                    # baseline + Rust/native + disposable Samba
./test.sh samba                   # disposable Samba only
./test.sh goad-discovery          # credential-free five-host discovery
./test.sh goad-full --windows-profile tests/interop/windows/profile.local.yml
./test.sh --help                  # all modes and options
```

Forward pytest arguments after `--`, for example
`./test.sh baseline -- -x -k compression`. Windows authenticated modes take an
ignored profile with `--windows-profile`; `destructive` and `goad-full`
additionally require the profile safety gates and
`AIOSMB_CONFIRM_DESTRUCTIVE=YES`. `goad-full` enables every GOAD group,
including inventory, normal-user, RPC, privileged, destructive, and
compression coverage.

The optional native compression companion implements unchained LZNT1, LZ77,
LZ77+Huffman, and LZ4. Full mode installs it and runs its Rust tests
automatically. The ordinary baseline suite uses the Python fallback and does
not require Rust or Docker.

The configured `pytest-randomly` seed is fixed so ordering and per-test random
state are reproducible. Pass another `--randomly-seed` to reproduce a reported
seed deliberately. Asyncio runs in strict mode, and the default per-test
timeout is 30 seconds.

For a manual branch-coverage run inside an existing environment:

```bash
PYTHONHASHSEED=0 python -m pytest tests/unit \
  --cov=aiosmb --cov-branch --cov-report=term-missing
```

## Layout

- `unit/`: deterministic tests with no network access.
- `fake_peer/`: async connection tests against scripted in-process peers.
- `component/`: tests spanning multiple repository components.
- `interop/samba/`: explicitly configured Samba interoperability.
- `interop/windows/`: capability-driven Windows lab interoperability.
- `fixtures/`: sanitized, non-secret test vectors.
- `support/`: reusable test-only helpers.
- `known_failures.yml`: confirmed production defects and blocker links.

## Marker and safety policy

Every test uses one primary scope marker: `unit`, `fake_peer`, `component`,
`samba`, or `windows`. Add `slow`, `destructive`, `privileged`, `quarantine`,
and `capability("name")` as applicable.

Samba, Windows, slow, destructive, privileged, and quarantine tests are
skipped unless their matching `--run-*` option is supplied. Capabilities are
declared with repeatable `--capability NAME` options. A test carrying multiple
gates must satisfy every gate. Never use an opt-in as a substitute for a
disposable target, least-privilege credentials, or a cleanup plan.

The default suite requires no Samba or Windows infrastructure. Local target
profiles and secrets must use the ignored `profile.local.yml` or
`profiles.local/` locations documented under `interop/`.

## Results and production defects

- Pass tests for supported behavior.
- Use strict `xfail` for one minimal reproducer of a confirmed production
  defect or planned feature, and reference its stable known-failure ID.
- Skip only when the platform, lab, credential tier, or capability is absent.
- Quarantine unsafe, flaky, or not-yet-classified cases.
- Mark downstream scenarios blocked by a canonical known failure instead of
  duplicating the same root defect.

Do not fix production code while developing this suite. Add or update
`known_failures.yml` with sanitized evidence, affected profiles, and blocker
relationships, then request a separate production-fix review.

## CI and live-lab tiers

The workflows under `.github/workflows/` deliberately separate trust and
infrastructure boundaries:

- `test-suite.yml` runs `unit`, `fake_peer`, and `component` tests for pull
  requests and pushes on Python 3.8 and the current Python. It publishes branch
  coverage, JUnit, and aggregate sanitized reports. A separate job enforces the
  known-failure registry contract.
- `samba-lab.yml` is scheduled and manually dispatchable. It invokes the
  pinned disposable lab through `tests/interop/samba/run-lab.sh`; it is never
  part of the default local or pull-request suite.
- `goad-readonly.yml` is manual-only and requires an isolated, explicitly
  labelled self-hosted runner plus a protected GitHub environment. Its normal
  tier uses only the basic-user environments. The optional privileged tier is
  read-only and separately gated. Neither job passes `--run-destructive`.

Live credentials belong only in protected CI secrets mapped directly to the
environment-variable names in `goad.example.yml`. Do not place values in
commands, profiles, logs, cache keys, step outputs, report labels, or artifact
names. The GOAD controller captures and redacts test output before upload.

The default local command remains infrastructure-free:

```console
PYTHONHASHSEED=0 python -m pytest
```

Samba and Windows tests are collected but skipped unless their explicit gates
and profiles are provided.

The SMB 2.0.2 server also has a local `smbclient` acceptance gate that does
not use the disposable Samba server lab:

```console
AIOSMB_RUN_LOCAL_SMBCLIENT=1 python -m pytest \
  tests/component/server_relay/test_smbclient_interop.py --run-samba
```

This requires the Samba `smbclient` executable. The test starts an authenticated
`aiosmb` server on a temporary loopback port and exercises file and directory
CRUD against a temporary share.
