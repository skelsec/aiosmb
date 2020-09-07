import datetime
import io

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/2c57429b-fdd4-488f-b5fc-9e4cf020fcdf
class FILETIME:
	def __init__(self):
		self.dwLowDateTime = None
		self.dwHighDateTime = None
		
		self.datetime = None
	@staticmethod
	def from_bytes(data):
		return FILETIME.from_buffer(io.BytesIO(data))

	def calc_dt(self):
		if self.dwHighDateTime == 4294967295 and self.dwLowDateTime == 4294967295:
			self.datetime = self.datetime = datetime.datetime(3000, 1, 1, 0, 0)
		else:
			ft = (self.dwHighDateTime << 32) + self.dwLowDateTime
			if ft == 0:
				self.datetime = datetime.datetime(1970, 1, 1, 0, 0)
			else:
				self.datetime = datetime.datetime.utcfromtimestamp((ft - 116444736000000000) / 10000000)
	
	@staticmethod
	def from_dict(d):
		t = FILETIME()
		t.dwLowDateTime = d['dwLowDateTime']
		t.dwHighDateTime = d['dwHighDateTime']
		t.calc_dt()
		return t

	@staticmethod
	def from_buffer(buff):
		t = FILETIME()
		t.dwLowDateTime = int.from_bytes(buff.read(4), byteorder='little', signed = False)
		t.dwHighDateTime = int.from_bytes(buff.read(4), byteorder='little', signed = False)
		t.calc_dt()
		return t