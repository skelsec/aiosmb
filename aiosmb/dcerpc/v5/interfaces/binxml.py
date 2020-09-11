
import io
import enum

class BinXMLToken(enum.Enum):
	EOF = b'\x00'
	#OpenStartElement = %x01 / %x41
	CloseStartElement = b'\x02' #Emit using CloseStartElementToken Rule
	CloseEmptyElement = b'\x03' #Emit using CloseEmptyElementToken Rule
	EndElement = b'\x04' #Emit using EndElementToken Rule
				
	#ValueText = %x05 / %x45
	#Attribute = %x06 / %x46
	#CDATASection = %x07 / %x47
	#CharRef = %x08 / %x48
	#EntityRef = %x09 / %x49
				
	PITarget = b'\x0A'
	PIData = b'\x0B'
	TemplateInstance = b'\x0C'
	NormalSubstitution = b'\x0D'
	OptionalSubstitution = b'\x0E'
	FragmentHeader = b'\x0F'

class BinXMLFragment:
	def __init__(self):
		self.x = None
		self.major = None
		self.minor = None
		self.flags = None

	@staticmethod
	def from_bytes(data):
		return BinXMLFragment.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		res = BinXMLFragment()
		hdr = buff.read(1)
		if hdr != b'\x0F':
			raise Exception('No fragment header!')
		res.major = int.from_bytes(buff.read(1), byteorder = 'little', signed=False)
		res.minor = int.from_bytes(buff.read(1), byteorder = 'little', signed=False)
		res.flags = int.from_bytes(buff.read(1), byteorder = 'little', signed=False)
		if res.flags  != 0:
			raise Exception('suspicious!')

		#here be a token or element!
		t = buff.read(1)
		if t == b'\x01' or t == b'\x41':
			#openstartelementtoken
			raise Exception('this route is not yet implemented!')
		
		elif t == b'\x0C':
			#templateinstance
			this_should_be_zero = int.from_bytes(buff.read(1), byteorder = 'little', signed=False)
			templateid = buff.read(8)
			print(templateid)

		

		return res