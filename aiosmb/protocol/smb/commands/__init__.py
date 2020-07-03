from aiosmb.protocol.smb.commands.negotiate import SMB_COM_NEGOTIATE_REQ, SMB_COM_NEGOTIATE_REPLY

#add new commands as they are implemented.
#do not forget to add the same commands to command_cdoes as well!


__all__ = [
	'SMB_COM_NEGOTIATE_REQ',
	'SMB_COM_NEGOTIATE_REPLY',

]