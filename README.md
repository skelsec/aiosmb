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
  
