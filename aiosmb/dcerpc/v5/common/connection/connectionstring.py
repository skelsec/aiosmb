import re


class DCERPCStringBinding:
	parser = re.compile(r'(?:([a-fA-F0-9-]{8}(?:-[a-fA-F0-9-]{4}){3}-[a-fA-F0-9-]{12})@)?' # UUID (opt.)
						+'([_a-zA-Z0-9]*):' # Protocol Sequence
						+'([^\[]*)' # Network Address (opt.)
						+'(?:\[([^\]]*)\])?') # Endpoint and options (opt.)

	def __init__(self, stringbinding):
		match = DCERPCStringBinding.parser.match(stringbinding)
		self.__uuid = match.group(1)
		self.__ps = match.group(2)
		self.__na = match.group(3)
		options = match.group(4)
		if options:
			options = options.split(',')
			self.__endpoint = options[0]
			try:
				self.__endpoint.index('endpoint=')
				self.__endpoint = self.__endpoint[len('endpoint='):]
			except:
				pass
			self.__options = options[1:]
		else:
			self.__endpoint = ''
			self.__options = []

	def get_uuid(self):
		return self.__uuid

	def get_protocol_sequence(self):
		return self.__ps

	def get_network_address(self):
		return self.__na

	def get_endpoint(self):
		return self.__endpoint

	def get_options(self):
		return self.__options

	def __str__(self):
		return DCERPCStringBindingCompose(self.__uuid, self.__ps, self.__na, self.__endpoint, self.__options)
		
def DCERPCStringBindingCompose(uuid=None, protocol_sequence='', network_address='', endpoint='', options=[]):
	s = ''
	if uuid: s += uuid + '@'
	s += protocol_sequence + ':'
	if network_address: s += network_address
	if endpoint or options:
		s += '[' + endpoint
		if options: s += ',' + ','.join(options)
		s += ']'

	return s