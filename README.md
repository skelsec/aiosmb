# aiosmb
Fully asynchronous SMB library written in pure python. Python 3.7+ ONLY

# IMPORTANT
It is far from ready. There are TONS of things to do to make this library usable for production.  

# What is expected
A lot of bugs and weird crashes. That aside, I believe I can bring this project to a stable version so you will be able to use it to perform normal operations as well as security ones as well.

# TODO
- Authentication to fully support SPNEGO with SSPI : DONE (SMB only, DCERPC ongoing)
- Have nice interface for reading/writing files: Ongoing, reading works now but far from ready
- Interface for qurying file/folder/pipe/... information: The logic is there, now it's just muscle-work to have all descriptor objects implemented
- Interface for creating files and folders: not yet
- DCERPC:
  - Not going to lie, I'm ripping off impacket for this one. The whole DCERPC is a mess as a protocol. A word for whoever designed it: you are a bad person.
  - Interface for controlling services: object is ready and stable, but missing a lot of functionalities
  - Interface for controlling registry: object is ready and stable, but missing a lot of functionalities
  - Interface for controlling drsuapi: in plans. First I want to get DCERPC to support Kerberos and or SPNEGO. Only NTLM works for now.
  - Any other RPC interfaces: not started or not even ready for testing.
  
# Connection url
I managed to condense all information needed to specify an SMB connection into an URL format.  
It looks like this:  
  
`dialect+authmethod://user:secret@target:port/?param1=value1`  
  
`dialect` fomat:  `smbX_version`  
Where `X`: `1` or `2`  
Where `version`: `200` or `201` or `300`...  
  
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

#### Example 1 - NTLM with password
`smb+ntlm-password://TEST\victim:Passw0rd!1@10.10.10.2`
#### Example 2 - NTLM with NT hash
`smb+ntlm-nt://TEST\victim:f8963568a1ec62a3161d9d6449baba93@10.10.10.2`
#### Example 3 - NTLM using the SSPI in Windows
`smb+sspi-ntlm://10.10.10.2`
#### Example 4 - KERBEROS with password
`smb+kerberos-password://TEST\victim:Passw0rd!1@10.10.10.2`
#### Example 5 - KERBEROS with NT hash
`smb+kerberos-nt://TEST\victim:f8963568a1ec62a3161d9d6449baba93@win2019ad.test.corp`
#### Example 6 - KERBEROS using the SSPI in Windows
`smb+sspi-kerberos://win2019ad.test.corp`
