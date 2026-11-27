# Component tests

Component tests exercise contracts spanning multiple in-repository pieces,
including the supported test server, high-level interfaces, scanners, CLI
boundaries, and packaging. Mark them `component` and keep them local and
deterministic; live Samba and Windows behavior belongs under `tests/interop/`.
