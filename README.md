# aiosmb
Fully asynchronous SMB library written in pure python. Python 3.7+ ONLY

# Features

## Authentication
### Kerberos
|           | Kirbi                 | CCACHE | AES/RC4/DES keys | NT hash | Password |
|-----------|-----------------------|--------|------------------|---------|----------|
| Supported | Y (convert to CCACHE) | Y      | Y                | Y       | Y        |

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

## Proxy
Supports Socks4 and Socks5 natively. Socks5 currently not supporting authentication.  
Bear in mind, that proxy support doesnt always play well with all auth methods, see this table below.

|          | SOCKS4                 | SOCKS5               |
|----------|------------------------|----------------------|
| NTLM     | Y                      | Y                    |
| Kerberos | N (incompatible)       | Y                    |
| SSPI     | Y (only local users)   | Y (only local users) |


# Connection url
I managed to condense all information needed to specify an SMB connection into an URL format.  
It looks like this:  
  
`dialect+authmethod://user:secret@target:port/?param1=value1`  
  
`dialect` fomat:  `smbX_version`  
Where `X`: `1` or `2`  
Where `version`: `200` or `201` or `300`...  
At the moment use only `smb` as this feature is not implemented.
  
`authmethod` format: `auth-type`  
Where `auth`: `ntlm` or `kerberos` or `sspi`  
Where `type`: `password` or `nt` or `aes` or `rc4` or `ccache` ...  
  
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
#### Example 6 - KERBEROS using the SSPI in Windows
`smb+sspi-kerberos://win2019ad.test.corp`
#### Example 7 - Socks proxy and NTLM with password
`smb+ntlm-password://TEST\victim:Passw0rd!1@10.10.10.2/?proxyhost=127.0.0.1&proxyport=9050`
#### Example 8 - NTLM with password with timeout higher than normal (60s)
`smb+ntlm-password://TEST\victim:Passw0rd!1@10.10.10.2/?timeout=60`

# TODO
- DCERPC:
  - Not going to lie, I'm ripping off impacket for this one. The whole DCERPC is a mess as a protocol. A word for whoever designed it: you are a bad person.
  - Interface for controlling services: object is ready and stable, but missing a lot of functionalities
  - Interface for controlling registry: object is ready and stable, but missing a lot of functionalities
  - Interface for controlling drsuapi: looking good.
  - Any other RPC interfaces: some implemented, some not.

# Kudos
This project is heavily based on the [Impacket project](https://github.com/SecureAuthCorp/impacket) orignally by @agsolino.  
The DCERPC strucutre definitions and DCERPC parsing in this project is almost identical to the Impacket project.
