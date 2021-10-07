import io
import enum
import uuid

class PresentationSyntax:
	def __init__(self):
		self.if_uuid = None
		self.if_version = None
	
	@staticmethod
	def from_bytes(data):
		return PresentationSyntax.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		res = PresentationSyntax()
		res.if_uuid = uuid.UUID(bytes_le=buff.read(16))
		res.if_version = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		return res
	
	def __str__(self):
		return "PresentationSyntax UUID:%s VERSION: %s" % (self.if_uuid, self.if_version)
	
	def __repr__(self):
		return self.__str__()

