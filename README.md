![Supported Python versions](https://img.shields.io/badge/python-3.8+-blue.svg) [![Twitter](https://img.shields.io/twitter/follow/skelsec?label=skelsec&style=social)](https://twitter.com/intent/follow?screen_name=skelsec)

## :triangular_flag_on_post: Sponsors

If you like this project, consider purchasing licenses of [OctoPwn](https://octopwn.com/), our full pentesting suite that runs in your browser!  
For notifications on new builds/releases and other info, hop on to our [Discord](https://discord.gg/PM8utcNxMS)


# aiosmb
Fully asynchronous SMB library written in pure python. Python 3.8+ ONLY


## :triangular_flag_on_post: Runs in the browser

This project, alongside with many other pentester tools runs in the browser with the power of OctoPwn!  
Check out the community version at [OctoPwn - Live](https://live.octopwn.com/)

# Features
Too many to list here, please check the examples.

## Authentication
### Kerberos
|           | Kirbi | CCACHE | AES/RC4/DES keys | NT hash | Password | Certificate | Certificate (PFX/PEM) | Certstore (Windows) |
|-----------|-------|--------|------------------|---------|----------|-------------|-----------------------|---------------------|
| Supported | Y     | Y      | Y                | Y       | Y        | Y           | Y                     | Y                   |

### NTLM
|           | LM hash | NT hash | Password |
|-----------|---------|---------|----------|
| Supported | N       | Y       | Y        |

### SSPI
Only on Windows.  
This auth method uses the current user context. If you are NT/SYSTEM then it will use the machine account credentials.
|           | NTLM | Kerberos |
|-----------|------|----------|
| Supported | Y    | Y        |

### NEGOEX
|           | Certificate (PFX) | Certstore (Windows)     |
|-----------|-------------------|-------------------------|
| Supported | Y                 | Y (using current user)  |

## Connection
This library also supports QUIC connection to Azure hosts

| Protocol | Supproted |
|----------|-----------|
| UDP      | N         |
| TCP      | Y         |
| QUIC     | Y         |

### Optional SMB 3.1.1 compression

Client-side SMB compression is an optional native feature. When the companion
is installed, SMB 3.1.1 connections advertise its codecs automatically.
Without it, the base installation remains pure Python, logs one warning, omits
the compression capability, and continues normally:

```bash
python -m pip install "aiosmb[compression]"
```

The default preference is XPRESS/LZ77, XPRESS LZ77+Huffman, LZ4, then LZNT1.
Negotiation alone does not compress every request: shares carrying
`SMB2_SHAREFLAG_COMPRESS_DATA` activate compression automatically.
`compress=1` requests compression for all eligible READ/WRITE traffic. Use an
ordered allow-list to force or reprioritize codecs independently of that
policy:

```text
smb311+ntlm-password://DOMAIN\user:password@server/share?compress_algorithms=lz4,lz77
```

Accepted names are `lz77`, `lz77_huffman`, `lz4`, and `lznt1`.
`compress_min=4096` changes the minimum WRITE data segment considered for
compression. Small messages and segments that do not become smaller are sent
without a compression transform. READ requests carry the compressed-response
flag only after SMB 3.1.1 compression has been negotiated. The server's
`SMB2_SHAREFLAG_COMPRESS_DATA` is also retained as per-share policy, and
trailing `compress=True`/`False` overrides are available on the low-level
connection `read()` and `write()` methods.

The native companion implements unchained LZNT1, LZ77, LZ77+Huffman, and raw
LZ4 blocks. Windows Server 2022 supports the first three; SMB LZ4 requires
Windows 11 or Windows Server 2025. The historical pure-Python LZNT1 module is
retained only as a test/reference implementation and is never selected at
runtime. Server/relay compression, chained transforms, Pattern_V1, and
non-READ/WRITE request compression are not supported.

Compression runs in a bounded worker offload, but it still exchanges CPU time
for network bandwidth. Current optimized native benchmarks range from roughly
41 to 599 MiB/s for compression and 220 MiB/s to 1.8 GiB/s for decompression
on compressible workloads, depending on codec and data shape. Benchmark your
payloads and link before enabling it broadly.

The companion uses the CPython 3.9 stable ABI for Python 3.9 and newer. CI
currently validates a Linux x86-64 wheel; use a source build with Rust and
`maturin` where a release wheel is unavailable. If the companion is missing or
unusable, even explicit compression requests degrade safely to uncompressed
SMB after the one-time warning.

### SMB 2.0.2 file server

`aiosmb.server` provides an SMB 2.0.2 server backed by local directories. It
supports NTLM/SPNEGO with a configured password or NT hash, optional or
required HMAC-SHA256 signing, file and directory CRUD, metadata queries, and
read-only share discovery through `IPC$\srvsvc`.

The installed `aiosmb-server` command configures one or more shares directly:

```bash
aiosmb-server --host 0.0.0.0 --port 445 \
  --domain LAB --username alice --password secret \
  --share Data=/srv/aiosmb/data \
  --read-only-share Public=/srv/aiosmb/public \
  --require-signing
```

Run `aiosmb-server --help` for the NT-hash, server identity, and logging
options. Omitting `--username`, `--password`, and `--nt-hash` enables an
anonymous session:

```bash
aiosmb-server --share Public=/srv/aiosmb/public
```

The server logs client intent at info level, including authentication, share
connections, file/directory opens, directory listings, renames, truncation,
and deletion. Successful named NTLM authentication also logs the captured
hashcat-compatible NetNTLMv2 challenge-response; anonymous sessions have no
such hash. Treat server logs as credential-sensitive. Use `-v` for request
details such as read/write ranges and `-vv` only when raw SMB packet structure
dumps are needed.

`--disable-ess` (alias `--downgrade-ess`) clears
`NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY` from the NTLM challenge for
compatibility and downgrade testing. This affects negotiated session security;
it does not select NTLMv1 versus NTLMv2, which remains client policy.

Anonymous sessions cannot be combined with required SMB signing and are
disabled by many modern clients unless their local security policy explicitly
permits them. An `aiosmb` client requests this identity explicitly with:

```text
smb202+ntlm-none://server.example/Public
```

`ntlm-none` sends the NTLM anonymous wire form (empty user and domain, no NT
response) and a successful server response is tracked as an SMB null session
from `SMB2_SESSION_FLAG_IS_NULL`. A server-reported
`SMB2_SESSION_FLAG_IS_GUEST` is tracked separately as guest access. Neither
restricted session type has an SMB signing key. A named account with an empty
password is still `ntlm-password`, not `ntlm-none`; Kerberos `none` credentials
do not have anonymous/null-session semantics and are unsupported.

The equivalent credentialed programmatic setup is:

```python
import asyncio

from asysocks.unicomm.common.target import UniProto, UniTarget
from aiosmb.server.server import SMBServer, SMBServerSettings


async def main():
    settings = SMBServerSettings.from_password(
        username="alice",
        password="secret",
        domain="LAB",
    )
    settings.shares = {
        "Data": "/srv/aiosmb/data",
    }
    settings.RequireSigning = False

    server = SMBServer(
        UniTarget("0.0.0.0", 445, UniProto.SERVER_TCP),
        settings,
    )
    server_task, error = await server.run()
    if error is not None:
        raise error
    await server_task


asyncio.run(main())
```

Share roots must already exist and be directories. Request paths are confined
to their configured root, including symlink resolution. Use
`SMBServerSettings.from_nt_hash()` when storing an NT hash instead of a
password; use `SMBServerSettings.from_anonymous()` for anonymous sessions.
Setting `RequireSigning = True` rejects unsigned authenticated requests;
signed responses use the NTLM session key.

The supported server profile is intentionally narrow: SMB 2.0.2, one local
filesystem backend, ordinary non-durable handles, and NDR32 `srvsvc`
`NetrShareEnum`, `NetrShareGetInfo`, and `NetrServerGetInfo`. SMB 2.1/3.x
features, encryption, compression, leases/oplocks, durable handles,
multichannel, notifications, byte-range locks, NDR64, and RPC-level
authentication/signing/sealing are not implemented.

### Proxy
Supports Socks4 and Socks5 natively. Socks5 currently not supporting authentication.  
Bear in mind, that proxy support doesnt always play well with all auth methods, see this table below.

|          | SOCKS4                 | SOCKS4A | SOCKS5               |
|----------|------------------------|---------|----------------------|
| NTLM     | Y                      | Y       | Y                    |
| Kerberos | N (incompatible)       | Y       | Y                    |
| SSPI     | Y (only local users)   | Y (only local users)      | Y (only local users) |
| NEGOEX   | Y                      | Y       | Y                    |


# Connection url
I managed to condense all information needed to specify an SMB connection into an URL format.  
It looks like this:  
  
`dialect-network+authmethod://user:secret@target:port/?param1=value1&param2=value2`  
  
`dialect` fomat:  `smbX/smbXXX`  
Where `version`: `2` for any `SBM2` `3` for any `SMB3` dialects, or specific 3 character code like `200` or `201` or `300`...  
  
`network` format: `tcp` or `quic` (leave empty for TCP)  

`authmethod` format: `auth-type`  
Where `auth`: `ntlm` or `kerberos` or `sspi` or `negext`
Where `type`: `password` or `nt` or `aes` or `rc4` or `kirbi` ...  
For native NTLM anonymous access, use `ntlm-none` without user information or
a secret. `none` is not a Kerberos authentication type.
  
`user` format: `DOMAIN\username`  
Where `DOMAIN`: your domain  
Where `username`: your username  
  
`secret` format: Depends on the `authmethod`'s `type` value  
`target` format: IP address or hostname of the target  
`port` format: integer describing the port  


### Example
The following parameters are used (the user victim is trying to log in to the domain controller):
Username: `victim`  
Domain: `TEST`  
Passowrd: `Passw0rd!1`  
DC IP address: `10.10.10.2`  
DC hostname: `win2019ad`  
Socks4 proxy serer: `127.0.0.1`
Socks4 proxy port : `9050`

#### Example 1 - NTLM with password
`smb+ntlm-password://TEST\victim:Passw0rd!1@10.10.10.2`
#### Example 2 - NTLM with NT hash
`smb+ntlm-nt://TEST\victim:f8963568a1ec62a3161d9d6449baba93@10.10.10.2`
#### Example 3 - NTLM using the SSPI in Windows
`smb+sspi-ntlm://10.10.10.2`
#### Example 4 - KERBEROS with password
`smb+kerberos-password://TEST\victim:Passw0rd!1@10.10.10.2/?dc=10.10.10.2`
#### Example 5 - KERBEROS with NT hash
`smb+kerberos-nt://TEST\victim:f8963568a1ec62a3161d9d6449baba93@win2019ad.test.corp/?dc=10.10.10.2`
#### Example 6 - KERBEROS with PFX certificate
`smb2+kerberos-pfx://user.pfx:password@win2019ad.test.corp/?dc=10.10.10.2`
#### Example 7 - KERBEROS with PEM certificate
`smb2+kerberos-pem://cert.pem:key.pem@win2019ad.test.corp/?dc=10.10.10.2`
#### Example 7 - KERBEROS with certificate from windows certificate store
`smb2+kerberos-pem://cert.pem:key.pem@win2019ad.test.corp/?dc=10.10.10.2`
#### Example 8 - KERBEROS using the SSPI in Windows
`smb+sspi-kerberos://win2019ad.test.corp`
#### Example 9 - Socks proxy and NTLM with password
`smb+ntlm-password://TEST\victim:Passw0rd!1@10.10.10.2/?proxyhost=127.0.0.1&proxyport=9050`
#### Example 10 - NTLM with password with timeout higher than normal (60s)
`smb+ntlm-password://TEST\victim:Passw0rd!1@10.10.10.2/?timeout=60`
#### Example 11 - Negoex certificate auth using PFX file. (eg. Azure P2P auth)
`smb+negoex-pfx://certificate.pfx:certpass@10.10.10.2/`
#### Example 12 - Negoex certstore auth using certificate from the current user's certstore (Windows only). (eg. Azure P2P auth)
`smb+negoex-certstore://<subject CN of the certificate to use>@10.10.10.2/`

# TODO
- DCERPC: in progress, lot of features working already
- VSS mountpoint operations
- a lot of other things

# Kudos
This project is heavily based on the [Impacket](https://github.com/SecureAuthCorp/impacket) orignally by @agsolino.  
The DCERPC strucutre definitions and DCERPC parsing in this project is almost identical to the Impacket project.  
NEGOEX protocol implementation was based on [AzureADJoinedMachinePTC](https://github.com/morRubin/AzureADJoinedMachinePTC) created by @rubin_mor  
Certificate request functionality was based on [certi](https://github.com/zer1t0/certi) created by @zer1t0

