class SMBConnectionTimeoutException(Exception):
	pass
	
class SMBConnectionRefusedException(Exception):
	pass
	
class SMBUnsupportedDialectSelected(Exception):
	pass

class SMBUnsupportedDialectSign(Exception):
	pass
	
class SMBUnsupportedSMBVersion(Exception):
	pass
	
class SMBKerberosPreauthFailed(Exception):
	pass

class SMBAuthenticationFailed(Exception):
	pass
	
class SMBGenericException(Exception):
	pass
	
class SMBIncorrectShareName(Exception):
	pass
	
class SMBCreateAccessDenied(Exception):
	pass