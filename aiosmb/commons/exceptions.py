
class SMBException(Exception):
	def __init__(self, message = '', ntstatus = None):
		super().__init__(message)
		self.ntstatus = ntstatus

	def pprint(self):
		return 'Error! Server responded with: %s' % self.ntstatus.name

class SMBConnectionNetworkTerminated(SMBException):
	pass

class SMBConnectionTimeoutException(SMBException):
	pass
	
class SMBConnectionRefusedException(SMBException):
	pass
	
class SMBUnsupportedDialectSelected(SMBException):
	pass

class SMBUnsupportedDialectSign(SMBException):
	pass
	
class SMBUnsupportedSMBVersion(SMBException):
	pass
	
class SMBKerberosPreauthFailed(SMBException):
	pass

class SMBAuthenticationFailed(SMBException):
	pass
	
class SMBGenericException(SMBException):
	pass
	
class SMBIncorrectShareName(SMBException):
	pass
	
class SMBCreateAccessDenied(SMBException):
	pass

class SMBPendingTimeout(SMBException):
	pass

class SMBPendingMaxRenewal(SMBException):
	pass


##### not SMBException from this point!
class SMBMachineException(Exception):
	def __init__(self, message = ''):
		super().__init__(message)

class SMBSocks5ConnectionError(Exception):
	def __init__(self, message = ''):
		super().__init__(message)
