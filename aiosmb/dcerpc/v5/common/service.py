import enum

class SMBServiceStatus(enum.Enum):
	CONTINUE_PENDING = 'CONTINUE_PENDING'
	PAUSE_PENDING = 'PAUSE_PENDING'
	PAUSED = 'PAUSED'
	RUNNING = 'RUNNING'
	START_PENDING = 'START_PENDING'
	STOP_PENDING = 'STOP_PENDING'
	STOPPED = 'STOPPED'
	DISABLED = 'DISABLED'
	UNKNOWN = 'UNKNOWN'

class SMBService:
	def __init__(self,name = None, display_name = None, status = None):
		self.name = name
		self.display_name = display_name
		self.status = status

	def __str__(self):
		return '%s - %s - %s' % (self.name, self.display_name, self.status.value)
