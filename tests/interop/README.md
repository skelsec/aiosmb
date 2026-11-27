# Interoperability tests

Live tests are opt-in and capability-driven. Commit only secret-free example
profiles; keep active inventories in `profile.local.yml` or `profiles.local/`.
Credentials must come from environment variables or the lab secret store and
must never be logged.

Default runs are read-only and non-privileged. Destructive or privileged tests
must carry all applicable markers and require their explicit command-line
gates in addition to an allow-listed, disposable target and a verified cleanup
or snapshot-restore path.
