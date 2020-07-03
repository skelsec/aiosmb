import enum

class EnumResultStatus(enum.Enum):
	RESULT = 'RESULT'
	FINISHED = 'FINISED'
	ERROR = 'ERROR'

class EnumResult:
	def __init__(self, target_id, target, result, error = None, status = EnumResultStatus.RESULT):
		self.target_id = target_id
		self.target = target
		self.error = error
		self.result = result
		self.status = status
