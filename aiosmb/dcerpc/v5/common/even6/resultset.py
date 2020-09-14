
import io


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-even6/762528ba-f36a-4d17-ba2b-0f0244a45f2f
class RESULT_SET:
	def __init__(self):
		self.totalSize = None
		self.headerSize = None
		self.eventOffset = None
		self.bookmarkOffset = None
		self.binXmlSize = None
		self.eventData = None
		self.numberOfSubqueryIDs = None
		self.subqueryIDs = None
		self.bookMarkData = None
	
	@staticmethod
	def from_bytes(data):
		return RESULT_SET.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		r = RESULT_SET()
		pos = buff.tell()
		r.totalSize = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		pos += r.totalSize
		r.headerSize = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		r.eventOffset = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		r.bookmarkOffset = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		r.binXmlSize = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		r.eventData = buff.read(r.binXmlSize)
		r.numberOfSubqueryIDs = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		r.subqueryIDs = buff.read(r.numberOfSubqueryIDs)
		r.bookMarkData = buff.read(pos - buff.tell())
		return r