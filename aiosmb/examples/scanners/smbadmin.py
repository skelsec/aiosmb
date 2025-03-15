
from asysocks.unicomm.common.scanner.common import *
from aiosmb.commons.connection.factory import SMBConnectionFactory
from aiosmb.commons.interfaces.share import SMBShare
from aiosmb.dcerpc.v5.interfaces.remoteregistry import RRPRPC
from aiosmb.dcerpc.v5.interfaces.servicemanager import REMSVCRPC
import traceback

class SMBAdminRes:
	def __init__(self, share, servicemgr, registry):
		self.share = share
		self.servicemgr = servicemgr
		self.registry = registry

	def get_header(self):
		return ['SHARE', 'SERVICE', 'REGISTRY']

	def to_line(self, separator = '\t'):
		return separator.join([str(self.share), str(self.servicemgr), str(self.registry)])
	
	def to_dict(self):
		return {
			'SHARE' : self.share,
			'SERVICE' : self.servicemgr,
			'REGISTRY' : self.registry
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
				#_, err = await rrp.connect()
				registry_access = True if err is None else False


				srvmgr, err = await REMSVCRPC.from_smbconnection(connection)
				#_, err = await srvmgr.connect()
				service_access = True if err is None else False
				

				await out_queue.put(ScannerData(target, SMBAdminRes(share_access, service_access, registry_access)))
				
		except Exception as e:
			tb = traceback.format_exc().replace('\n', ' ').replace('\r', '')
			await out_queue.put(ScannerError(target, f"{e} | Traceback: {tb}"))
