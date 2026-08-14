
from asysocks.unicomm.common.scanner.common import *
from aiosmb.commons.connection.factory import SMBConnectionFactory
from aiosmb.commons.interfaces.share import SMBShare
from aiosmb.dcerpc.v5.interfaces.remoteregistry import RRPRPC, REG_ACCESS_MASK
from aiosmb.dcerpc.v5.interfaces.servicemanager import REMSVCRPC
import traceback

class SMBAdminRes:
	def __init__(self, share, servicemgr, registry):
		self.share = share
		self.servicemgr = servicemgr
		self.registry = registry
		self.admin = any([self.share, self.servicemgr])

	def get_header(self):
		return ['SHARE', 'SERVICE', 'REGISTRY', 'ADMIN']

	def to_line(self, separator = '\t'):
		return separator.join([str(self.share), str(self.servicemgr), str(self.registry), str(self.admin)])
	
	def to_dict(self):
		return {
			'SHARE' : self.share,
			'SERVICE' : self.servicemgr,
			'REGISTRY' : self.registry,
			'ADMIN' : self.admin
		}

class SMBAdminScanner:
	def __init__(self, factory:SMBConnectionFactory):
		self.factory:SMBConnectionFactory = factory

	async def run(self, targetid, target, out_queue):
		try:
			connection = self.factory.create_connection_newtarget(target)
			async with connection:
				_, err = await connection.login()
				if err is not None:
					raise err
				
				share_access = False
				service_access = False
				registry_access = False

				share = SMBShare(
					name = 'ADMIN$',
					fullpath = '\\\\%s\\%s' % (connection.target.get_hostname_or_ip(), 'ADMIN$')
				)
				_, err = await share.connect(connection)
				if err is not None:
					share_access = False
					share = SMBShare(
						name = 'admin$',
						fullpath = '\\\\%s\\%s' % (connection.target.get_hostname_or_ip(), 'admin$')
					)
					_, err = await share.connect(connection)
					share_access = True if err is None else False
				else:
					share_access = True

				rrp, err = await RRPRPC.from_smbconnection(connection)
				if err is None:
					_, err = await rrp.OpenRegPath(
						r'HKEY_LOCAL_MACHINE\SOFTWARE',
						access = REG_ACCESS_MASK.KEY_CREATE_SUB_KEY | REG_ACCESS_MASK.KEY_SET_VALUE
					)
					registry_access = True if err is None else False
					await rrp.close()


				srvmgr, err = await REMSVCRPC.from_smbconnection(connection)
				#_, err = await srvmgr.connect()
				service_access = True if err is None else False
				

				await out_queue.put(ScannerData(target, SMBAdminRes(share_access, service_access, registry_access)))
				
		except Exception as e:
			tb = traceback.format_exc().replace('\n', ' ').replace('\r', '')
			await out_queue.put(ScannerError(target, f"{e} | Traceback: {tb}"))
