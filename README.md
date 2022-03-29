![Supported Python versions](https://img.shields.io/badge/python-3.7+-blue.svg) [![Twitter](https://img.shields.io/twitter/follow/skelsec?label=skelsec&style=social)](https://twitter.com/intent/follow?screen_name=skelsec)

:triangular_flag_on_post: This is the public repository of aioSMB, for latest version and updates please consider supporting us through https://porchetta.industries/

# aiosmb
Fully asynchronous SMB library written in pure python. Python 3.7+ ONLY

## :triangular_flag_on_post: Sponsors

If you want to sponsors this project and have the latest updates on this project, latest issues fixed, latest features, please support us on https://porchetta.industries/

## Official Discord Channel

Come hang out on Discord!

[![Porchetta Industries](https://discordapp.com/api/guilds/736724457258745996/widget.png?style=banner3)](https://discord.gg/ycGXUxy)


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

