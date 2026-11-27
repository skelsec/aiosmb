# Test support

Reusable test-only builders, scripted transports, capability loaders, and
sanitizers belong here. Support code must not open external connections during
import or collection, and it must remain independent of credentials and local
lab profiles.

Keep protocol assertions in their owning test modules so helpers do not become
an alternative implementation that can agree with the production bug.

## Sanitized CI reports

`reporting.py` reads one or more pytest JUnit files and emits aggregate JSON
and Markdown. It reports only pass, skip, xfail, and fail totals plus stable
`KF-NNNN` identifiers. Test names, class names, diagnostics, hostnames, input
paths, and captured output are never copied into its artifacts.

```console
python tests/support/reporting.py \
  --junit test-results/junit.xml \
  --registry tests/known_failures.yml \
  --json-output reports/test-summary.json \
  --markdown-output reports/test-summary.md
```

Repeat `--junit` to combine controller invocations. To report registry changes,
also pass a trusted base-revision copy with `--baseline-registry`. The tool
reports added and removed IDs plus status/classification transitions; it does
not copy titles or evidence. Malformed inputs fail closed without echoing XML,
YAML, or file paths.

JUnit remains an upstream test-runner artifact and can contain failure
diagnostics. General CI has no credentials. The Windows controller separately
redacts credential environment values before its JUnit and text artifacts are
uploaded.
