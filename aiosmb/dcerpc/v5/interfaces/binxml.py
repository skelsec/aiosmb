
import io
import enum
import struct

from aiosmb.wintypes.dtyp.constrcuted_security.guid import GUID
from aiosmb.wintypes.dtyp.constrcuted_security.sid import SID


class Fragment:
	def __init__(self):
		self.FragmentHeaders = []
		self.values = []

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

	@staticmethod
	def from_buffer(buff):
		ti = TemplateInstance()
		
		ti.TemplateInstanceToken = buff.read(1)
		print(b'aaaa' + peek_buffer(buff, 100))
		ti.TemplateDef = TemplateDef.from_buffer(buff)
		ti.TemplateInstanceData = TemplateInstanceData.from_buffer(buff)
		print(ti.TemplateInstanceData.Values)
		for i in ti.TemplateDef.Elements:
			print(i)
			if isinstance(i, StartElement):
				if i.AttributeList is not None:

					print('    %s : %s' % (i.Name.value, i.AttributeList.Attributes ))
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
			if isinstance(v, EOF):
				break
			#td.FragmentHeaders.append(v)
			#v = parse_next(buff, (Element, StartElement, Substitution, EndElement, ValueText, EOF))
			td.Elements.append(v)
			#if isinstance(v, EOF):
			#	break

		return td
	
#	@staticmethod
#	def from_buffer(buff):
#		td = TemplateDef()
#		
#		td.dunno = buff.read(1) #docu sais it's \xb0 but itts not
#		print('td.dunno %s' % td.dunno)
#		td.TemplateId = GUID.from_buffer(buff)
#		print(td.TemplateId)
#		td.TemplateDefByteLength = int.from_bytes(buff.read(4), byteorder = 'little', signed=False)
#		print('td.TemplateDefByteLength %s' % td.TemplateDefByteLength)
#		
#		pd = peek_buffer(buff)
#		if pd == b'\x00':
#			return td
#		elif pd == b'\x0F':
#			td.FragmentHeader = FragmentHeader.from_buffer(buff)
#		while True:
#			print('b4 elem end %s' % peek_buffer(buff, 100))
#			td.Elements.append(Element.from_buffer(buff))
#			end = peek_buffer(buff)
#			if end == b'\x00':
#				buff.read(1)
#				break
#			elif end == b'\x04':
#				print('!!!!!!!!!!!!!!!!!!!!!!!!!!')
#				buff.read(1)
#				sub = Substitution.from_buffer(buff)
#				if peek_buffer(buff) == b'\x04':
#					buff.read(1)
#					if peek_buffer(buff) == b'\x00':
#						buff.read(1)
#						break
#					print('b4 elem end %s' % peek_buffer(buff, 100))
#					break
#				
#				
#				continue
#				#td.Elements.append(Element.from_buffer(buff))
#
#			
#		print('end: %s' % end)
#		print('TemplateDef end %s' % peek_buffer(buff, 100))
#		return td

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
		#raise Exception('gell')
		print('vs.NumValues %s' % vs.NumValues)
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
		el.StartElement = parse_next(buff, (StartElement,)) #StartElement.from_buffer(buff)

		t = parse_next(buff, (CloseStartElement, CloseEmptyElement))
		if isinstance(t, CloseEmptyElement): 
			return el
		
		while True:
			t = parse_next(buff, (CloseStartElement, CloseEmptyElement))
			el.Contents.append(t)
			if isinstance(t, EndElement):
				return el

		#t = buff.read(1)
		#if t == b'\x02':
		#	while True:
		#		print(1)
		#		Content = parse_next(buff)
		#		if isinstance(Content, EndElement):
		#			break
		return el


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

	@staticmethod
	def from_buffer(buff):
		se = StartElement()
		se.OpenStartElementToken = buff.read(1)
		print('OpenStartElementToken %s' % se.OpenStartElementToken)
		se.DependencyId = int.from_bytes(buff.read(2), byteorder = 'little', signed=False)
		se.ElementByteLength = int.from_bytes(buff.read(4), byteorder = 'little', signed=False)
		print('se.ElementByteLength: %s' % se.ElementByteLength)
		se.Name = Name.from_buffer(buff)
		print('se.Name %s' % se.Name.value)
		if se.OpenStartElementToken == b'\x41':
			print('gere')
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
		
		print('%s : %s' % (vt.Name.value, vt.AttributeCharData.value.value))
		return vt

class AttributeCharData:
	def __init__(self):
		self.AttributeToken = None
		self.value = None

	@staticmethod
	def from_buffer(buff):
		vt = AttributeCharData()
		vt.value = parse_next(buff)
		return vt

class AttributeList:
	def __init__(self):
		self.AttributeListByteLength = None
		self.Attributes = []

	@staticmethod
	def from_buffer(buff):
		vt = AttributeList()
		vt.AttributeListByteLength = int.from_bytes(buff.read(4), byteorder = 'little', signed=False)
		pos = buff.tell() + vt.AttributeListByteLength
		while buff.tell() != pos :
			print(1)
			vt.Attributes.append(Attribute.from_buffer(buff))
		
		return vt

class ValueText:
	def __init__(self):
		self.ValueTextToken = None
		self.StringType = None
		self.value = None

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
		#print(Name_val)
		n.value = Name_val.decode('utf-16-le')
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
	print('decode_val %s : %s' % (data_type, data))
	if data_type == ValueType.NullType:
		return None
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
		return None
	elif data_type == ValueType.FileTimeType:
		return None
	elif data_type == ValueType.SysTimeType:
		return None
	elif data_type == ValueType.SidType:
		return SID.from_bytes(data)
	elif data_type == ValueType.HexInt32Type:
		return None
	elif data_type == ValueType.HexInt64Type:
		return None
	elif data_type == ValueType.BinXmlType:
		return Fragment.from_bytes(data)
	
	
	return None

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
