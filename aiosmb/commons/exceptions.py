
class SMBException(Exception):
	def __init__(self, message = '', ntstatus = None):
		super().__init__('%s Status: %s' % (message, ntstatus))
		self.ntstatus = ntstatus

	def pprint(self):
		return 'Error! Server responded with: %s' % self.ntstatus.name

class SMBConnectionNetworkTerminated(SMBException):
	def __init__(self, msg = ''):
		if len(msg) == 0:
			super().__init__('ConnectionTerminated',-1)
		else:
			super().__init__(msg,-1)

class SMBConnectionTimeoutException(SMBException):
	def __init__(self, msg = ''):
		if len(msg) == 0:
			super().__init__('ConnectionTimeout',-1)
		else:
			super().__init__(msg,-1)
	
class SMBConnectionRefusedException(SMBException):
	def __init__(self, msg = ''):
		if len(msg) == 0:
			super().__init__('ConnectionRefused',-1)
		else:
			super().__init__(msg,-1)
	
class SMBUnsupportedDialectSelected(SMBException):
	def __init__(self, msg = ''):
		if len(msg) == 0:
			super().__init__('UnsupportedDialect',-1)
		else:
			super().__init__(msg,-1)

class SMBUnsupportedDialectSign(SMBException):
	def __init__(self, msg = ''):
		if len(msg) == 0:
			super().__init__('UnsupportedDialectSign',-1)
		else:
			super().__init__(msg,-1)
	
class SMBUnsupportedSMBVersion(SMBException):
	def __init__(self, msg = ''):
		if len(msg) == 0:
			super().__init__('UnsupportedSMBVersion',-1)
		else:
			super().__init__(msg,-1)
	
class SMBKerberosPreauthFailed(SMBException):
	def __init__(self, msg = ''):
		if len(msg) == 0:
			super().__init__('KerberosPreauthFailed',-1)
		else:
			super().__init__(msg,-1)

class SMBAuthenticationFailed(SMBException):
	def __init__(self, msg = ''):
		if len(msg) == 0:
			super().__init__('SMBAuthenticationFailed',-1)
		else:
			super().__init__(msg,-1)
	
class SMBGenericException(SMBException):
	def __init__(self, msg = ''):
		if len(msg) == 0:
			super().__init__('GenericException',-1)
		else:
			super().__init__(msg,-1)
	
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
