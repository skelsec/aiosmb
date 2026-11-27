# SMB server and relay component tests

The server tests cover the supported SMB 2.0.2 profile without changing the
separate relay implementation:

- wire correlation, compounds, credits, signing, lifecycle, and errors;
- local-backend containment, handle state, and file/directory CRUD;
- required SMB and FSCC serializers;
- named-pipe transport, fragmented NDR32 DCE/RPC, and read-only `srvsvc`;
- real-socket acceptance with authenticated and `ntlm-none` anonymous
  production `aiosmb` clients.

Run the deterministic server coverage with:

```bash
python -m pytest tests/component/server_relay -m "component and not samba"
```

The local Samba client gate starts the `aiosmb` server on a temporary TCP port
and runs `smbclient` against it. It requires the `smbclient` executable and an
explicit opt-in:

```bash
AIOSMB_RUN_LOCAL_SMBCLIENT=1 python -m pytest \
  tests/component/server_relay/test_smbclient_interop.py --run-samba
```

It validates `ls`, `put`, `get`, `rename`, `del`, `mkdir`, and `rmdir` for a
credentialed session, plus anonymous upload/download/delete using
`smbclient -N -U %`. All shares and credentials are temporary test values; no
external SMB target is used.
