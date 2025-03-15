
from asysocks.unicomm.common.scanner.common import *
from aiosmb.commons.connection.factory import SMBConnectionFactory
from aiosmb.commons.interfaces.machine import SMBMachine


class SMBFileRes:
	def __init__(self, obj, otype, err):
		self.obj = obj
		self.otype = otype
		self.err = err

		self.unc_path = ''
		self.creationtime = ''
		self.size = ''
		self.sizefmt = ''
		self.security_descriptor_sddl = ''

		self.process()
	

	# https://stackoverflow.com/questions/1094841/get-human-readable-version-of-file-size
	@staticmethod
	def sizeof_fmt(num, suffix='B'):
		if num is None:
			return ''
		for unit in ['','Ki','Mi','Gi','Ti','Pi','Ei','Zi']:
			if abs(num) < 1024.0:
				return "%3.1f%s%s" % (num, unit, suffix)
			num /= 1024.0
		return "%.1f%s%s" % (num, 'Yi', suffix)

	def get_header(self):
		return ['otype', 'path', 'creationtime', 'size', 'sizefmt', 'sddl']
	
	def process(self):
		if self.err is not None:
			try:
				self.unc_path = str(self.obj.unc_path)
			except:
				pass
		
		if self.otype in ['dir', 'file', 'share']:
			self.unc_path = str(self.obj.unc_path)
			if self.otype == 'dir' or self.otype == 'file' or self.otype == 'share':
				if self.otype == 'dir' or self.otype == 'file':
					if self.obj.creation_time is not None:
						self.creationtime = self.obj.creation_time.isoformat()
				security_descriptor = self.obj.security_descriptor
				self.security_descriptor_sddl = '' if security_descriptor is None else str(security_descriptor.to_sddl())
			
			if self.otype == 'file':
				self.size = self.obj.size
				self.sizefmt = SMBFileRes.sizeof_fmt(self.size)

	def to_line(self, separator = '\t'):
		if self.err is not None:
			return separator.join([
				'err',
				self.unc_path,
				'',
				'0',
				'',
				str(self.err)
			])
		if self.otype == 'file':
			return separator.join([
				'file',
				self.unc_path,
				self.creationtime,
				str(self.size), 
				self.sizefmt,
				self.security_descriptor_sddl,
			])
		if self.otype == 'dir':
			return separator.join([
				'dir',
				self.unc_path, 
				self.creationtime, 
				'0',
				'',
				self.security_descriptor_sddl
			])
		if self.otype == 'share':
			return separator.join([
				'share',
				self.unc_path,
				'',
				'0',
				'',
				self.security_descriptor_sddl
			])
		
		return separator.join([
			'unknown',
			self.unc_path,
			self.creationtime,
			self.size,
			self.sizefmt,
			self.security_descriptor_sddl
		])
	
	def to_dict(self):
		if self.err is not None:
			return {
				'otype' : 'err',
				'path' : self.unc_path,
				'err' : str(self.err)
			}
		if self.otype == 'file':
			return {
				'otype' : 'file',
				'path' : self.unc_path,
				'creationtime' : self.creationtime,
				'size' : self.size,
				'sizefmt' : self.sizefmt,
				'sddl' : self.security_descriptor_sddl
			}
		if self.otype == 'dir':
			return {
				'otype' : 'dir',
				'path' : self.unc_path,
				'creationtime' : self.creationtime,
				'sddl' : self.security_descriptor_sddl
			}
		if self.otype == 'share':
			return {
				'otype' : 'share',
				'path' : self.unc_path,
				'sddl' : self.security_descriptor_sddl
			}
		
		return {
			'otype' : 'unknown',
			'path' : self.unc_path,
			'creationtime' : self.creationtime,
			'size' : self.size,
			'sizefmt' : self.sizefmt,
			'sddl' : self.security_descriptor_sddl
		}


class SMBFileScanner:
	def __init__(self, 
			factory:SMBConnectionFactory, 
			depth = 3,
			max_items = None, 
			fetch_share_sd = False, 
			fetch_dir_sd=False, 
			fetch_file_sd = False,
			exclude_share = [],
			exclude_dir = []
			):
		
		self.factory = factory
		self.depth = depth 
		self.maxentries = max_items
		self.fetch_share_sd= fetch_share_sd 
		self.fetch_dir_sd = fetch_dir_sd
		self.fetch_file_sd = fetch_file_sd 
		self.exclude_share = exclude_share 
		self.exclude_dir = exclude_dir

	async def run(self, targetid, target, out_queue):
		try:
			connection = self.factory.create_connection_newtarget(target)
			async with connection:
				_, err = await connection.login()
				if err is not None:
					raise err

				machine = SMBMachine(connection)
				async for obj, otype, err in machine.enum_all_recursively(
						depth = self.depth, 
						maxentries = self.maxentries, 
						fetch_share_sd= self.fetch_share_sd, 
						fetch_dir_sd = self.fetch_dir_sd, 
						fetch_file_sd = self.fetch_file_sd, 
						exclude_share = self.exclude_share, 
						exclude_dir = self.exclude_dir):

					await out_queue.put(ScannerData(target, SMBFileRes(obj, otype, err)))

		except Exception as e:
			await out_queue.put(ScannerError(target, e))
