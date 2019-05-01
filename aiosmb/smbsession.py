class SMBSession:
	"""
	"""
	def __init__(self):
		self.SessionID = 0
		self.TreeConnectTable = {}
		self.SessionKey = ''
		self.SigningRequired = ''
		self.Connection = 0
		self.OpenTable = {}
		
		self.ChannelList = []
		self.ChannelSequence = 0
	
	
		