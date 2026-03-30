
from asysocks.unicomm.common.scanner.common import *
from aiosmb.commons.connection.factory import SMBConnectionFactory
from aiosmb.commons.interfaces.machine import SMBMachine


class SMBShareRes:
	def __init__(self, share, writable, err):
		self.share = share
		self.writable = writable
		self.err = err

	def get_header(self):
		return ['path', 'writable', 'description', 'access', 'sddl']

	def to_line(self, separator = '\t'):
			if self.err is not None:
				unc_path = ''
				try:
					unc_path = str(self.share.unc_path)
				except:
					pass
				return separator.join([
					unc_path,
					'',
					'',
					'',
					str(self.err)
				])
			
			unc_path = str(self.share.unc_path)
			security_descriptor_sddl = '' if self.share.security_descriptor is None else str(self.share.security_descriptor.to_sddl())
				
			return separator.join([
					unc_path,
					str(self.writable),
					str(self.share.remark) if self.share.remark is not None else '',
					str(self.share.maximal_access),
					security_descriptor_sddl,
				])
	
	def to_dict(self):
		if self.err is not None:
			return {
				'path' : str(self.share.unc_path),
				'writable' : '',
				'description' : '',
				'access' : '',
				'sddl' : str(self.err),
				'sddlhex' : ''
			}
		
		security_descriptor_sddl = '' if self.share.security_descriptor is None else str(self.share.security_descriptor.to_sddl())
		security_descriptor_sddl_hex = '' if self.share.security_descriptor is None else self.share.security_descriptor.to_bytes().hex()

		return {
			'path' : str(self.share.unc_path),
			'writable' : str(self.writable),
			'description' : str(self.share.remark) if self.share.remark is not None else '',
			'access' : str(self.share.maximal_access),
			'sddl' : security_descriptor_sddl,
			'sddlhex' : security_descriptor_sddl_hex
		}

class SMBShareScanner:
	def __init__(self, 
			factory:SMBConnectionFactory, 
			test_write:bool = False,
			fetch_share_sd:bool = False
			):
		
		self.factory = factory
		self.test_write = test_write
		self.fetch_share_sd = fetch_share_sd

	async def run(self, targetid, target, out_queue):
		try:
			connection = self.factory.create_connection_newtarget(target)
			async with connection:
				_, err = await connection.login()
				if err is not None:
					raise err

				machine = SMBMachine(connection)
				if self.test_write is False:
					async for share, err in machine.list_shares(fetch_share_sd = self.fetch_share_sd):
						await out_queue.put(ScannerData(target, SMBShareRes(share, None, err)))
				else:
					async for share, writable, err in machine.share_write_test(fetch_share_sd = self.fetch_share_sd):
						await out_queue.put(ScannerData(target, SMBShareRes(share, writable, err)))

		except Exception as e:
			await out_queue.put(ScannerError(target, e))
