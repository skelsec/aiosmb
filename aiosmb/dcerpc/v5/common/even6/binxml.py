
import io
import enum
import struct
from xml.dom.minidom import parseString

from aiosmb.wintypes.dtyp.constrcuted_security.guid import GUID
from aiosmb.wintypes.dtyp.constrcuted_security.sid import SID
from aiosmb.wintypes.dtyp.structures.filetime import FILETIME

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-even6/c73573ae-1c90-43a2-a65f-ad7501155956

class Fragment:
	def __init__(self):
		self.FragmentHeaders = []
		self.values = []

	def to_xml(self):
		t = ''
		for v in self.values:
			t += v.to_xml()
		return t

	@staticmethod
	def from_bytes(data):
		return Fragment.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		ti = Fragment()
		while True:
			v = parse_next(buff, (FragmentHeader, EOF))
			if isinstance(v, EOF):
				break
			ti.FragmentHeaders.append(v)
			v = parse_next(buff, (Element, TemplateInstance))
			ti.values.append(v) 
		return ti

class FragmentHeader:
	def __init__(self):
		self.FragmentHeaderToken = None
		self.major = None
		self.minor = None
		self.flags = None

	@staticmethod
	def from_buffer(buff):
		res = FragmentHeader()
		res.FragmentHeaderToken = buff.read(1)
		res.major = int.from_bytes(buff.read(1), byteorder = 'little', signed=False)
		res.minor = int.from_bytes(buff.read(1), byteorder = 'little', signed=False)
		res.flags = int.from_bytes(buff.read(1), byteorder = 'little', signed=False)
		if res.major != 1:
			raise Exception('FragmentHeader err')
		return res


class TemplateInstance:
	def __init__(self):
		self.TemplateInstanceToken = None
		self.TemplateDef = None
		self.TemplateInstanceData = None

	def to_xml(self):
		xml_elements = []
		open_tags = []
		

		i = 0
		while i < len(self.TemplateDef.Elements):
			el = self.TemplateDef.Elements[i]
			if isinstance(el, StartElement):
				open_tags.append(el.Name.value)
				if isinstance(self.TemplateDef.Elements[i + 1], CloseStartElement):
					xml_elements.append(el.to_xml(self.TemplateInstanceData))
					i += 2
					continue

				if isinstance(self.TemplateDef.Elements[i + 1], CloseEmptyElement):
					open_tags.pop(-1)
					xml_elements.append(el.to_xml(self.TemplateInstanceData, is_empty = True))
					i += 2
					continue
				

			elif isinstance(el, Substitution):
				if el.token == b'\x0E':
					list_replacement = isinstance(self.TemplateInstanceData.Values[el.SubstitutionId], list)
					if self.TemplateInstanceData.ValueSpec.ValueSpecEntries[el.SubstitutionId].ValueType == ValueType.NullType or list_replacement:
						open_tags.pop(-1)
						xml_elements.pop(-1)
						n = 1
						while True:
							if isinstance(self.TemplateDef.Elements[i + n], EndElement):
								n += 1 # increasing by 2 so we skip the endelement which would cause an error of popping an empty list
								continue
							break
						i += n
						if list_replacement:
							xml_elements.append(el.to_xml(self.TemplateInstanceData))
						continue
				
				xml_elements.append(el.to_xml(self.TemplateInstanceData))

			elif isinstance(el, ValueText):
				xml_elements.append(el.to_xml())

			elif isinstance(el, EndElement):
				xml_elements.append('</%s>' % open_tags.pop(-1))
			
			elif isinstance(el, EOF):
				while len(open_tags) != 0:
					xml_elements.append('</%s>' % open_tags.pop(-1))
			
			else:
				raise Exception('Element not processed! %s' % el.to_xml())

			i+= 1

		return '\r\n'.join(xml_elements)

	@staticmethod
	def from_buffer(buff):
		ti = TemplateInstance()
		ti.TemplateInstanceToken = buff.read(1)
		ti.TemplateDef = TemplateDef.from_buffer(buff)
		ti.TemplateInstanceData = TemplateInstanceData.from_buffer(buff)
		ti.to_xml()

		return ti

class TemplateDef:
	def __init__(self):
		self.dunno = None
		self.TemplateId = None
		self.TemplateDefByteLength = None
		self.FragmentHeader = None
		self.Elements = []

	@staticmethod
	def from_buffer(buff):
		td = TemplateDef()
		td.dunno = buff.read(1) #docu sais it's \xb0 but itts not
		td.TemplateId = GUID.from_buffer(buff)
		td.TemplateDefByteLength = int.from_bytes(buff.read(4), byteorder = 'little', signed=False)

		td.FragmentHeader = parse_next(buff, (FragmentHeader,))
		while True:
			v = parse_next(buff, (Element, StartElement, CloseStartElement, CloseEmptyElement, Substitution, EndElement, ValueText, EOF))
			td.Elements.append(v)
			if isinstance(v, EOF):
				break

		return td

class TemplateInstanceData:
	def __init__(self):
		self.ValueSpec = None
		self.Values = []
	
	@staticmethod
	def from_buffer(buff):
		tid = TemplateInstanceData()
		
		tid.ValueSpec = ValueSpec.from_buffer(buff)
		for vp in tid.ValueSpec.ValueSpecEntries:
			val = decode_val(buff.read(vp.ValueByteLength), vp.ValueType)
			tid.Values.append(val)

		return tid

class ValueSpec:
	def __init__(self):
		self.NumValues = None
		self.ValueSpecEntries = []

	@staticmethod
	def from_buffer(buff):
		vs = ValueSpec()
		vs.NumValues = int.from_bytes(buff.read(4), byteorder = 'little', signed=False)
		for _ in range(vs.NumValues):
			vs.ValueSpecEntries.append(ValueSpecEntry.from_buffer(buff))
		return vs

class ValueSpecEntry:
	def __init__(self):
		self.ValueByteLength = None
		self.ValueType = None

	@staticmethod
	def from_buffer(buff):
		vs = ValueSpecEntry()
		vs.ValueByteLength = int.from_bytes(buff.read(2), byteorder = 'little', signed=False)
		vs.ValueType = ValueType(buff.read(1))
		zero = buff.read(1)
		return vs

class Element:
	def __init__(self):
		self.StartElement = None
		self.Contents = []

	@staticmethod
	def from_buffer(buff):
		el = Element()
		el.StartElement = parse_next(buff, (StartElement,))

		t = parse_next(buff, (CloseStartElement, CloseEmptyElement))
		el.Contents.append(t)
		if isinstance(t, CloseEmptyElement): 
			return el
		
		while True:
			t = parse_next(buff, (CloseStartElement, CloseEmptyElement))
			el.Contents.append(t)
			if isinstance(t, EndElement):
				return el

		return el

## this class is bundled in with the Element class, no need for it separately
#class Content:
#	def __init__(self):
#		pass
#	
#	@staticmethod
#	def from_buffer(buff):
#		return parse_next(buff)


class CharData:
	def __init__(self):
		pass
	
	@staticmethod
	def from_buffer(buff):
		return parse_next(buff)

class StartElement:
	def __init__(self):
		self.OpenStartElementToken = None
		self.DependencyId = None
		self.ElementByteLength = None
		self.Name = None
		self.AttributeList = None

	def to_xml(self, subtable = None, is_empty = False):
		if self.AttributeList is None:
			return '<%s>' % (self.Name.value)
		else:
			t = '<%s ' % (self.Name.value)
			t += self.AttributeList.to_xml(subtable)
			t += '>' if is_empty is False else ' />'
		return t

	@staticmethod
	def from_buffer(buff):
		se = StartElement()
		se.OpenStartElementToken = buff.read(1)
		se.DependencyId = int.from_bytes(buff.read(2), byteorder = 'little', signed=False)
		se.ElementByteLength = int.from_bytes(buff.read(4), byteorder = 'little', signed=False)
		se.Name = Name.from_buffer(buff)
		if se.OpenStartElementToken == b'\x41':
			se.AttributeList = AttributeList.from_buffer(buff)
		return se

class Attribute:
	def __init__(self):
		self.AttributeToken = None
		self.Name = None
		self.AttributeCharData = None

	@staticmethod
	def from_buffer(buff):
		vt = Attribute()
		vt.AttributeToken = buff.read(1)
		vt.Name = Name.from_buffer(buff)
		vt.AttributeCharData = AttributeCharData.from_buffer(buff)
		return vt

class AttributeCharData:
	def __init__(self):
		self.AttributeToken = None
		self.value = None

	def to_xml(self, subtable = None):
		return self.value.to_xml(subtable)

	@staticmethod
	def from_buffer(buff):
		vt = AttributeCharData()
		vt.value = parse_next(buff)
		return vt

class AttributeList:
	def __init__(self):
		self.AttributeListByteLength = None
		self.Attributes = []

	def to_xml(self, subtable = None):
		t = []
		for attr in self.Attributes:
			t.append('%s="%s"' % (attr.Name.value, attr.AttributeCharData.to_xml(subtable)))
		return ' '.join(t)

	@staticmethod
	def from_buffer(buff):
		vt = AttributeList()
		vt.AttributeListByteLength = int.from_bytes(buff.read(4), byteorder = 'little', signed=False)
		pos = buff.tell() + vt.AttributeListByteLength
		while buff.tell() != pos :
			vt.Attributes.append(Attribute.from_buffer(buff))
		
		return vt

class ValueText:
	def __init__(self):
		self.ValueTextToken = None
		self.StringType = None
		self.value = None

	def to_xml(self, subtable = None):
		return self.value

	@staticmethod
	def from_buffer(buff):
		vt = ValueText()
		vt.ValueTextToken = buff.read(1)
		vt.StringType = buff.read(1)
		vt.value = read_LengthPrefixedUnicodeString(buff)
		return vt

class Substitution:
	def __init__(self):
		self.token = None
		self.SubstitutionId = None
		self.ValueType = None

		self.value = 'substitution'

	def to_xml(self, subtable = None):
		if self.ValueType == ValueType.BinXmlType:
			return subtable.Values[self.SubstitutionId].to_xml() #recursion much?!
		elif isinstance(subtable.Values[self.SubstitutionId], list):
			t = ''
			for x in subtable.Values[self.SubstitutionId]:
				if x == '':
					t += '<Data />'
				t += '<Data>%s</Data>' % x
			
			return t
		
		return str(subtable.Values[self.SubstitutionId])

		

	@staticmethod
	def from_buffer(buff):
		s = Substitution()
		s.token = buff.read(1)
		s.SubstitutionId = int.from_bytes(buff.read(2), byteorder = 'little', signed=False)
		s.ValueType = ValueType(buff.read(1))
		return s


class CharRef:
	def __init__(self):
		self.CharRefToken = None
		self.value = None

	@staticmethod
	def from_buffer(buff):
		er = CharRef()
		er.CharRefToken = buff.read(1)
		er.value = int.from_bytes(buff.read(2), byteorder = 'little', signed=False)
		return er

class EntityRef:
	def __init__(self):
		self.EntityRefToken = None
		self.Name = None

	@staticmethod
	def from_buffer(buff):
		er = EntityRef()
		er.EntityRefToken = buff.read(1)
		er.Name = Name.from_buffer(buff)
		return er

class CDATASection:
	def __init__(self):
		self.CDATASectionToken = None
		self.value = None

	@staticmethod
	def from_buffer(buff):
		cd = CDATASection()
		cd.CDATASectionToken = buff.read(1)
		cd.value = read_LengthPrefixedUnicodeString(buff)
		return cd

class PI:
	def __init__(self):
		self.PITarget = None
		self.PIData = None

	@staticmethod
	def from_buffer(buff):
		pi = PI()
		pi.PITarget = PITarget.from_buffer(buff)
		pi.PIData = Name.from_buffer(buff)
		return pi

class PIData:
	def __init__(self):
		self.PIDataToken = None
		self.value = None

	@staticmethod
	def from_buffer(buff):
		pid = PIData()
		pid.PIDataToken = buff.read(1)
		pid.value = read_LengthPrefixedUnicodeString(buff)
		return pid

class PITarget:
	def __init__(self):
		self.PITargetToken = None
		self.Name = None

	@staticmethod
	def from_buffer(buff):
		pit = PITarget()
		pit.PITargetToken = buff.read(1)
		pit.Name = Name.from_buffer(buff)
		return pit

class Name:
	def __init__(self):
		self.NameHash = None
		self.NameNumChars = None
		self.value = None

	@staticmethod
	def from_buffer(buff):
		n = Name()
		n.NameHash = int.from_bytes(buff.read(2), byteorder = 'little', signed=False)
		n.NameNumChars = int.from_bytes(buff.read(2), byteorder = 'little', signed=False)
		Name_val = buff.read((n.NameNumChars * 2) + 2)
		n.value = Name_val.decode('utf-16-le')[:-1]
		return n

class CloseStartElement:
	def __init__(self):
		self.token = None

	@staticmethod
	def from_buffer(buff):
		c = CloseStartElement()
		c.token = buff.read(1)
		return c

class CloseEmptyElement:
	def __init__(self):
		self.token = None

	@staticmethod
	def from_buffer(buff):
		c = CloseEmptyElement()
		c.token = buff.read(1)
		return c

class EndElement:
	def __init__(self):
		self.token = None

	@staticmethod
	def from_buffer(buff):
		c = EndElement()
		c.token = buff.read(1)
		return c

class EOF:
	def __init__(self):
		self.token = None
		self.value = None

	@staticmethod
	def from_buffer(buff):
		c = EOF()
		c.token = buff.read(1)
		return c


def peek_buffer(buff, length = 1):
	pos = buff.tell()
	data = buff.read(length)
	buff.seek(pos, 0)
	return data

def read_LengthPrefixedUnicodeString(buff):
	NumUnicodeChars = int.from_bytes(buff.read(2), byteorder = 'little', signed=False)
	StringValue = buff.read(NumUnicodeChars*2)
	return StringValue.decode('utf-16-le')

def parse_next(buff, expected = ()):
	t = token_node_lookup[peek_buffer(buff)].from_buffer(buff)
	if len(expected) == 0:
		return t
	if isinstance(t, expected):
		return t
	raise Exception('parse_next error! %s expected but %s found' % (expected, type(t)))

def decode_val(data, data_type):
	#print('decode_val %s : %s' % (data_type, data))
	if data_type == ValueType.NullType:
		return ''
	elif data_type == ValueType.StringType:
		return data.decode('utf-16-le')
	elif data_type == ValueType.AnsiStringType:
		return data.decode()
	elif data_type == ValueType.Int8Type:
		return int.from_bytes(data, byteorder = 'little', signed = True)
	elif data_type == ValueType.UInt8Type:
		return int.from_bytes(data, byteorder = 'little', signed = False)
	elif data_type == ValueType.Int16Type:
		return int.from_bytes(data, byteorder = 'little', signed = True)
	elif data_type == ValueType.UInt16Type:
		return int.from_bytes(data, byteorder = 'little', signed = False)
	elif data_type == ValueType.Int32Type:
		return int.from_bytes(data, byteorder = 'little', signed = True)
	elif data_type == ValueType.UInt32Type:
		return int.from_bytes(data, byteorder = 'little', signed = False)
	elif data_type == ValueType.Int64Type:
		return int.from_bytes(data, byteorder = 'little', signed = True)
	elif data_type == ValueType.UInt64Type:
		return int.from_bytes(data, byteorder = 'little', signed = False)
	elif data_type == ValueType.Real32Type:
		return struct.unpack('<f', data)
	elif data_type == ValueType.Real64Type:
		return struct.unpack('<d', data)
	elif data_type == ValueType.BoolType:
		return bool(int.from_bytes(data, byteorder = 'little', signed = False))
	elif data_type == ValueType.BinaryType:
		return data
	elif data_type == ValueType.GuidType:
		return GUID.from_bytes(data)
	elif data_type == ValueType.SizeTType:
		return '0x' + data[::-1].hex()
	elif data_type == ValueType.FileTimeType:
		return FILETIME.from_bytes(data).datetime.isoformat()
	elif data_type == ValueType.SysTimeType:
		return FILETIME.from_bytes(data).datetime.isoformat()
	elif data_type == ValueType.SidType:
		return SID.from_bytes(data)
	elif data_type == ValueType.HexInt32Type:
		return '0x' + data[::-1].hex()
	elif data_type == ValueType.HexInt64Type:
		return '0x' + data[::-1].hex()
	elif data_type == ValueType.BinXmlType:
		return Fragment.from_bytes(data)

	elif data_type == ValueType.StringArrayType:
		sa = []
		i = 0
		t = b''
		while i < len(data):
			t += data[i:i+1]
			if t[-3:] == b'\x00\x00\x00' or t == b'\x00\x00':
				sa.append(t.decode('utf-16-le')[:-1])
				t = b''
			i += 1
		return sa
	else:
		raise Exception('Unknown format! %s' % data_type)
	
	

token_node_lookup = {
	b'\x00' : EOF,
	b'\x01' : StartElement,
	b'\x41' : StartElement,
	b'\x02' : CloseStartElement,
	b'\x03' : CloseEmptyElement,
	b'\x04' : EndElement,
	b'\x05' : ValueText,
	b'\x45' : ValueText,
	b'\x06' : Attribute,
	b'\x46' : Attribute,
	b'\x07' : CDATASection,
	b'\x47' : CDATASection,
	b'\x08' : CharRef,
	b'\x48' : CharRef,
	b'\x09' : EntityRef,
	b'\x49' : EntityRef,
	b'\x0A' : PITarget,
	b'\x0B' : PIData,
	b'\x0C' : TemplateInstance,
	b'\x0D' : Substitution, #NormalSubstitution,
	b'\x0E' : Substitution, #OptionalSubstitution,
	b'\x0F' : FragmentHeader,
}

class ValueType(enum.Enum):
	NullType = b'\x00'
	StringType = b'\x01'
	AnsiStringType = b'\x02'
	Int8Type = b'\x03'
	UInt8Type = b'\x04'
	Int16Type = b'\x05'
	UInt16Type = b'\x06'
	Int32Type = b'\x07'
	UInt32Type = b'\x08'
	Int64Type = b'\x09'
	UInt64Type = b'\x0A'
	Real32Type = b'\x0B'
	Real64Type = b'\x0C'
	BoolType = b'\x0D'
	BinaryType = b'\x0E'
	GuidType = b'\x0F'
	SizeTType = b'\x10'
	FileTimeType = b'\x11'
	SysTimeType = b'\x12'
	SidType = b'\x13'
	HexInt32Type = b'\x14'
	HexInt64Type = b'\x15'
	BinXmlType = b'\x21'

	StringArrayType = b'\x81'
	AnsiStringArrayType = b'\x82'
	Int8ArrayType = b'\x83'
	UInt8ArrayType = b'\x84'
	Int16ArrayType = b'\x85'
	UInt16ArrayType = b'\x86'
	Int32ArrayType = b'\x87'
	UInt32ArrayType = b'\x88'
	Int64ArrayType = b'\x89'
	UInt64ArrayType = b'\x8A'
	Real32ArrayType = b'\x8B'
	Real64ArrayType = b'\x8C'
	BoolArrayType = b'\x8D'
	GuidArrayType = b'\x8F'
	SizeTArrayType = b'\x90'
	FileTimeArrayType = b'\x91'
	SysTimeArrayType = b'\x92'
	SidArrayType = b'\x93'
	HexInt32ArrayType = b'\x94' #also b'\x00'
	HexInt64ArrayType = b'\x95' #also b'\x00'
