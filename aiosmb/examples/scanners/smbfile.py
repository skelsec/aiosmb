
from asysocks.unicomm.common.scanner.common import *
from aiosmb.commons.connection.factory import SMBConnectionFactory
from aiosmb.commons.interfaces.machine import SMBMachine


class SMBFileRes:
	def __init__(self, obj, otype, err):
		self.obj = obj
		self.otype = otype
		self.err = err

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

	def to_line(self, separator = '\t'):
		if self.err is not None:
			unc_path = ''
			try:
				unc_path = str(self.obj.unc_path)
			except:
				pass
			return separator.join([
				'err',
				unc_path,
				str(self.err)
			])

		unc_path = ''
		creationtime = ''
		size = ''
		sizefmt = ''
		security_descriptor_sddl = ''
		if self.otype in ['dir', 'file', 'share']:
			unc_path = str(self.obj.unc_path)
			if self.otype == 'dir' or self.otype == 'file' or self.otype == 'share':
				if self.otype == 'dir' or self.otype == 'file':
					if self.obj.creation_time is not None:
						creationtime = self.obj.creation_time.isoformat()
				security_descriptor = self.obj.security_descriptor
				security_descriptor_sddl = '' if security_descriptor is None else str(security_descriptor.to_sddl())
			
			if self.otype == 'file':
				size = self.obj.size
				sizefmt = SMBFileRes.sizeof_fmt(size)

		if self.otype == 'file':
			return separator.join([
				'file',
				unc_path,
				creationtime,
				str(size), 
				sizefmt,
				security_descriptor_sddl,
			])
		if self.otype == 'dir':
			return separator.join([
				'dir',
				unc_path, 
				creationtime, 
				security_descriptor_sddl
			])
		if self.otype == 'share':
			return separator.join([
				'share',
				unc_path,
				security_descriptor_sddl
			])

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
