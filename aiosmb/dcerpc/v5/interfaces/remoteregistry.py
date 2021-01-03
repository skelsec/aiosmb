
import enum

from aiosmb.dcerpc.v5.common.connection.smbdcefactory import SMBDCEFactory
from aiosmb.dcerpc.v5 import rrp
from aiosmb.dcerpc.v5.interfaces.servicemanager import *
from aiosmb import logger
from aiosmb.dcerpc.v5 import system_errors
from aiosmb.wintypes.dtyp.structures.filetime import FILETIME
from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR
from aiosmb.wintypes.dtyp.constrcuted_security.security_information import SECURITY_INFORMATION

class HKEY(enum.Enum):
	CLASSES_ROOT = 0 #Registry entries subordinate to this key define types (or classes) of documents and the properties associated with those types. Shell and COM applications use the information stored under this key.
	CURRENT_USER = 1 #Registry entries subordinate to this key define the preferences of the current user. These preferences include the settings of environment variables, data about program groups, colors, printers, network connections, and application preferences.
	LOCAL_MACHINE = 2 #Registry entries subordinate to this key define the physical state of the computer, including data about the bus type, system memory, and installed hardware and software.
	USERS = 3 #Registry entries subordinate to this key define the default user configuration for new users on the local computer and the user configuration for the current user.
	PERFORMANCE_DATA = 4 #Registry entries subordinate to this key allow you to access performance data. The data is not actually stored in the registry; the registry functions cause the system to collect the data from its source.
	CURRENT_CONFIG = 5 #Contains information about the current hardware profile of the local computer system.
	DYN_DATA = 6 #This key is not used in versions of Windows after 98.

hkey_abbrev = {
	'HKEY_LOCAL_MACHINE' : HKEY.LOCAL_MACHINE,
	'HKLM' : HKEY.LOCAL_MACHINE,
	'HKEY_CURRENT_USER' : HKEY.CURRENT_USER,
	'HKCU' : HKEY.CURRENT_USER,
	'HKEY_CLASSES_ROOT' : HKEY.CLASSES_ROOT,
	'HKCR' : HKEY.CLASSES_ROOT,
	'HKEY_USERS' : HKEY.USERS,
	'HKU' : HKEY.USERS,
	'HKEY_PERFORMANCE_DATA' : HKEY.PERFORMANCE_DATA,
	'HKPD' : HKEY.PERFORMANCE_DATA,
	'HKEY_CURRENT_CONFIG' : HKEY.CURRENT_CONFIG,
	'HKCC' : HKEY.PERFORMANCE_DATA,
}

class REG_ACCESS_MASK(enum.IntFlag):
	GENERIC_READ            = 0x80000000
	GENERIC_WRITE           = 0x4000000
	GENERIC_EXECUTE         = 0x20000000
	GENERIC_ALL             = 0x10000000
	MAXIMUM_ALLOWED         = 0x02000000
	ACCESS_SYSTEM_SECURITY  = 0x01000000
	SYNCHRONIZE             = 0x00100000
	WRITE_OWNER             = 0x00080000
	WRITE_DACL              = 0x00040000
	READ_CONTROL            = 0x00020000
	DELETE                  = 0x00010000

class REG_VAL_TYPE(enum.Enum):
	BINARY              = 3
	DWORD               = 4
	DWORD_LITTLE_ENDIAN = 4
	DWORD_BIG_ENDIAN    = 5
	EXPAND_SZ           = 2
	LINK                = 6
	MULTI_SZ            = 7
	NONE                = 0
	QWORD               = 11
	QWORD_LITTLE_ENDIAN = 11
	SZ                  = 1 

def reg_decode_value(value_type, value_data):
	if value_type == REG_VAL_TYPE.SZ:
		return value_data.decode('utf-16-le')
	elif value_type in [REG_VAL_TYPE.DWORD, REG_VAL_TYPE.DWORD_LITTLE_ENDIAN]:
		return int.from_bytes(value_data, byteorder='little', signed = False)
	elif value_type == REG_VAL_TYPE.DWORD_BIG_ENDIAN:
		return int.from_bytes(value_data, byteorder='big', signed = False)
	elif value_type in [REG_VAL_TYPE.QWORD, REG_VAL_TYPE.QWORD_LITTLE_ENDIAN]:
		return int.from_bytes(value_data, byteorder='little', signed = False)
	
	return value_data

class RRP:
	def __init__(self, connection):
		self.connection = connection		
		self.dce = None
		self.handles = {}
		self.__current_handle_id = 0
	
	def __get_handle(self, hkey):
		hid = self.__current_handle_id
		self.__current_handle_id += 1
		self.handles[hid] = hkey
		return hid

	async def __get_rawhandle(self, key):
		if isinstance(key, HKEY):
			key, err = await self.ConnectRegistry(key)
			if err is not None:
				raise err
		
		return self.handles[key]

	async def __aenter__(self):
		return self
		
	async def __aexit__(self, exc_type, exc, traceback):
		await self.close()
		return True, None
	
	async def connect(self):
		try:
			rpctransport = SMBDCEFactory(self.connection,  filename=r'\winreg')
			self.dce = rpctransport.get_dce_rpc()
			_, err = await self.dce.connect()
			if err is not None:
				raise err
			_, err = await self.dce.bind(rrp.MSRPC_UUID_RRP)
			if err is not None:
				raise err
			return True, None
		except Exception as e:
			return None, e

	async def close(self):
		try:
			for hkey in self.handles:
				await self.CloseKey(hkey)

			await self.dce.disconnect()
		except Exception as e:
			return False, e

	async def CloseKey(self, key):
		try:
			key = await self.__get_rawhandle(key)
			_, err = await rrp.hBaseRegCloseKey(self.dce, key)
			if err is not None:
				raise err
			return True, None
		except Exception as e:
			if isinstance(e, rrp.DCERPCSessionError):
				return None, OSError(e.get_error_code(), system_errors.ERROR_MESSAGES[e.get_error_code()][1])
			return None, e

	async def ConnectRegistry(self, key, access = REG_ACCESS_MASK.MAXIMUM_ALLOWED):
		try:
			
			res = None
			err = None
			if key == HKEY.CLASSES_ROOT:
				res, err = await rrp.hOpenClassesRoot(self.dce, samDesired = access.value)

			elif key == HKEY.CURRENT_USER:
				res, err = await rrp.hOpenCurrentUser(self.dce, samDesired = access.value)
			
			elif key == HKEY.LOCAL_MACHINE:
				res, err = await rrp.hOpenLocalMachine(self.dce, samDesired = access.value)
			
			elif key == HKEY.USERS:
				res, err = await rrp.hOpenUsers(self.dce, samDesired = access.value)
			
			elif key == HKEY.PERFORMANCE_DATA:
				res, err = await rrp.hOpenPerformanceData(self.dce, samDesired = access.value)

			elif key == HKEY.CURRENT_CONFIG:
				res, err = await rrp.hOpenCurrentConfig(self.dce, samDesired = access.value)
			
			else:
				raise Exception('Not supported registry hive to open: %s' % key.name)
			
			if err is not None:
				return None, err

			return self.__get_handle(res['phKey']), None
		
		except Exception as e:
			if isinstance(e, rrp.DCERPCSessionError):
				return None, OSError(e.get_error_code(), system_errors.ERROR_MESSAGES[e.get_error_code()][1])
			return None, e

	async def CreateKey(self, key, sub_key, access=REG_ACCESS_MASK.MAXIMUM_ALLOWED):
		try:
			key = await self.__get_rawhandle(key)
			res, err = await rrp.hBaseRegCreateKey(self.dce, key, sub_key, samDesired = access.value)
			if err is not None:
				raise err

			return self.__get_handle(res['phkResult']), None
		except Exception as e:
			if isinstance(e, rrp.DCERPCSessionError):
				return None, OSError(e.get_error_code(), system_errors.ERROR_MESSAGES[e.get_error_code()][1])
			return None, e

	async def DeleteKey(self, key, sub_key):
		try:
			key = await self.__get_rawhandle(key)
			
			res, err = await rrp.hBaseRegDeleteKey(self.dce, key, sub_key)
			if err is not None:
				raise err	
			return True, None

		except Exception as e:
			if isinstance(e, rrp.DCERPCSessionError):
				return None, OSError(e.get_error_code(), system_errors.ERROR_MESSAGES[e.get_error_code()][1])
			return None, e

	async def DeleteValue(self, key, value):
		try:
			key = await self.__get_rawhandle(key)
			
			_, err = await  rrp.hBaseRegDeleteValue(self.dce, key, value)
			if err is not None:
				raise err
			
			return True, None
		
		except Exception as e:
			if isinstance(e, rrp.DCERPCSessionError):
				return None, OSError(e.get_error_code(), system_errors.ERROR_MESSAGES[e.get_error_code()][1])
			return None, e

	async def EnumKey(self, key, index):
		try:
			key = await self.__get_rawhandle(key)
			res, err = await rrp.hBaseRegEnumKey(self.dce, key, index)
			if err is not None:
				raise err
			return res['lpNameOut'], None
		
		except Exception as e:
			if isinstance(e, rrp.DCERPCSessionError):
				return None, OSError(e.get_error_code(), system_errors.ERROR_MESSAGES[e.get_error_code()][1])
			return None, e

	async def EnumValue(self, key, index):
		try:
			key = await self.__get_rawhandle(key)
			res, err = await rrp.hBaseRegEnumValue(self.dce, key, index)
			if err is not None:
				raise err
			
			value_name = res['lpValueNameOut']
			value_type = REG_VAL_TYPE(res['lpType'])
			value_data = reg_decode_value(value_type ,b''.join(res['lpData']))
			return value_name, value_type, value_data, None
		except Exception as e:
			if isinstance(e, rrp.DCERPCSessionError):
				return None, None, None, OSError(e.get_error_code(), system_errors.ERROR_MESSAGES[e.get_error_code()][1])
			return None, None, None, e

	async def FlushKey(self, key):
		try:
			key = await self.__get_rawhandle(key)
			_, err = await rrp.hBaseRegFlushKey(self.dce, key)
			return True, err
		except Exception as e:
			if isinstance(e, rrp.DCERPCSessionError):
				return None, OSError(e.get_error_code(), system_errors.ERROR_MESSAGES[e.get_error_code()][1])
			return None, e

	async def LoadKey(self, key, sub_key, file_name):
		try:
			key = await self.__get_rawhandle(key)
			_, err = await rrp.hBaseRegLoadKey(self.dce, key, sub_key, file_name)
			if err is not None:
				raise err

			return True, None
		except Exception as e:
			if isinstance(e, rrp.DCERPCSessionError):
				return None, OSError(e.get_error_code(), system_errors.ERROR_MESSAGES[e.get_error_code()][1])
			return None, e

	async def OpenKey(self, key, sub_key, reserved=0, access=REG_ACCESS_MASK.MAXIMUM_ALLOWED):
		try:
			key = await self.__get_rawhandle(key)
			res , err = await rrp.hBaseRegOpenKey(self.dce, key, sub_key, access.value)
			if err is not None:
				raise err
			return self.__get_handle(res['phkResult']), None
		
		except Exception as e:
			if isinstance(e, rrp.DCERPCSessionError):
				return None, OSError(e.get_error_code(), system_errors.ERROR_MESSAGES[e.get_error_code()][1])
			return None, e

	async def QueryInfoKey(self, key):
		try:
			key = await self.__get_rawhandle(key)
			res , err = await rrp.hBaseRegQueryInfoKey(self.dce, key)
			if err is not None:
				raise err
			
			subkey_cnt = res['lpcSubKeys']
			values_cnt = res['lpcValues']
			lastwrite_time = FILETIME.from_dict(res['lpftLastWriteTime']).datetime
			
			return subkey_cnt, values_cnt, lastwrite_time, None

		except Exception as e:
			if isinstance(e, rrp.DCERPCSessionError):
				return None, None, None, OSError(e.get_error_code(), system_errors.ERROR_MESSAGES[e.get_error_code()][1])
			return None, None, None, e
		

	async def GetKeySecurity(self, key, securityInformation = SECURITY_INFORMATION.OWNER):
		try:
			key = await self.__get_rawhandle(key)
			res , err = await rrp.hBaseRegGetKeySecurity(self.dce, key, securityInformation = securityInformation)
			if err is not None:
				raise err
			return SECURITY_DESCRIPTOR.from_bytes(res), None
		
		except Exception as e:
			if isinstance(e, rrp.DCERPCSessionError):
				return None, OSError(e.get_error_code(), system_errors.ERROR_MESSAGES[e.get_error_code()][1])
			return None, e

	async def QueryValue(self, key, value_name, unpack_vals = True):
		try:
			key = await self.__get_rawhandle(key)
			val_type, value , err = await rrp.hBaseRegQueryValue(self.dce, key, value_name, unpack_vals=unpack_vals)
			if err is not None:
				raise err
			return val_type, value, err
		except Exception as e:
			if isinstance(e, rrp.DCERPCSessionError):
				return None, None, OSError(e.get_error_code(), system_errors.ERROR_MESSAGES[e.get_error_code()][1])
			return None, None, e

	async def SaveKey(self, key, file_name):
		try:
			key = await self.__get_rawhandle(key)
			res , err = await rrp.hBaseRegSaveKey(self.dce, key, file_name)
			if err is not None:
				raise err

			return res, None
		except Exception as e:
			if isinstance(e, rrp.DCERPCSessionError):
				return None, OSError(e.get_error_code(), system_errors.ERROR_MESSAGES[e.get_error_code()][1])
			return None, e

	async def SetValue(self, key, sub_key, val_type, val_data):
		
		#the packing is done in the original layer, not sure if everything works but it seems so
		try:
			key = await self.__get_rawhandle(key)
			res, err =  await rrp.hBaseRegSetValue(self.dce, key, sub_key, val_type.value, val_data)
			if err is not None:
				raise err
			return True, None
		except Exception as e:
			if isinstance(e, rrp.DCERPCSessionError):
				return None, None, OSError(e.get_error_code(), system_errors.ERROR_MESSAGES[e.get_error_code()][1])
			return None, None, e

	async def OpenPerformanceText(self):
		try:
			res , err = await rrp.hOpenPerformanceText(self.dce)
			if err is not None:
				raise err
			return res['phKey'], None
		except Exception as e:
			if isinstance(e, rrp.DCERPCSessionError):
				return None, None, OSError(e.get_error_code(), system_errors.ERROR_MESSAGES[e.get_error_code()][1])
			return None, None, e

	async def OpenPerformanceNlsText(self):
		try:
			res , err = await rrp.hOpenPerformanceNlsText(self.dce)
			if err is not None:
				raise err
			return res['phKey'], None
		except Exception as e:
			if isinstance(e, rrp.DCERPCSessionError):
				return None, None, OSError(e.get_error_code(), system_errors.ERROR_MESSAGES[e.get_error_code()][1])
			return None, None, e

	async def OpenRegPath(self, fullpath, access = REG_ACCESS_MASK.MAXIMUM_ALLOWED):
		try:
			reg_root, key_path = fullpath.split('\\',1)
			root_key = hkey_abbrev[reg_root]

			key, err = await self.ConnectRegistry(root_key, access = access)
			if err is not None:
				return None, err
			return await self.OpenKey(key, key_path, access = access)
		except Exception as e:
			if isinstance(e, rrp.DCERPCSessionError):
				return None, None, OSError(e.get_error_code(), system_errors.ERROR_MESSAGES[e.get_error_code()][1])
			return None, e




################## CUT HERE
class PERF_OBJECT_TYPE:
	def __init__(self):
		self.TotalByteLength = None
		self.DefinitionLength = None
		self.HeaderLength = None
		self.ObjectNameTitleIndex = None
		self.ObjectNameTitle = None
		self.ObjectHelpTitleIndex = None
		self.ObjectHelpTitle = None
		self.DetailLevel = None
		self.NumCounters = None
		self.DefaultCounter = None
		self.NumInstances = None
		self.CodePage = None
		self.PerfTime = None
		self.PerfFreq = None
		self.TotalByteLength = None
		self.TotalByteLength = None
		self.TotalByteLength = None

async def preftest(rs):
	pref_handle, err = await rs.ConnectRegistry(HKEY.PERFORMANCE_DATA)
	if err is not None:
		print('users error! %s' % err)
		return

	val_type, val_data, err = await rs.QueryValue(pref_handle, 'Counter 009', unpack_vals=False)
	if err is not None:
		print(traceback.format_tb(err.__traceback__))
		print('users error! %s' % err)
		return

	print(val_data[:100])

	return

async def OpenRegPathTest(rs):
	hk, err = await rs.OpenRegPath(r'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion')
	print(err)

	res, err = await rs.QueryInfoKey(hk)
	print(res.dump())

	for i in range(200):
		value_name, value_type, value_data, err = await rs.EnumValue(hk, i)
		if err is not None:
			if err.errno == 259: #no more data is available
				break
			print(traceback.format_tb(err.__traceback__))
		print(value_data)

	return

async def ConnectRegistryTest(rs):
	import traceback
	users_handle, err = await rs.ConnectRegistry(HKEY.USERS)
	if err is not None:
		print('users error! %s' % err)
		return
	print('user handle: %s' % users_handle)
	for i in range(10):
		res, err = await rs.EnumKey(users_handle, i)
		if err is not None:
			if err.errno == 259: #no more data is available
				break
			print(err)
			print(traceback.format_tb(err.__traceback__))
		print(res)
	
	res, err = await rs.OpenKey(users_handle, "S-1-5-21-3448413973-1765323015-1500960949-500")
	if err is not None:
		print('openkey failed! %s' % err)
	
	print(res)
	
	for i in range(10):
		value_name, value_type, value_data, err = await rs.EnumValue(res, i)
		if err is not None:
			if err.errno == 259: #no more data is available
				break
			print(err)
			print(traceback.format_tb(err.__traceback__))
		print(value_data)

async def amain():
	from aiosmb.commons.connection.url import SMBConnectionURL
	from aiosmb.connection import SMBConnection
	import traceback

	url = 'smb2+kerberos-password://TEST\\Administrator:QLFbT8zkiFGlJuf0B3Qq@win2019ad.test.corp?serverip=10.10.10.2&dc=10.10.10.2'
	su = SMBConnectionURL(url)
	conn = su.get_connection()

	_, err = await conn.login()
	if err is not None:
		print(err)
		return
	else:
		print('SMB Connected!')
	rs = RRP(conn)
	_, err = await rs.connect()
	if err is not None:
		print(err)
		return
	print('RRP Connected!')


	await ConnectRegistryTest(rs)


	res, err = await rs.OpenRegPath(r'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run')
	if err is not None:
		print(err)
	
	subkey_cnt, values_cnt, lastwrite_time, err = await rs.QueryInfoKey(res)
	if err is not None:
		print(err)
	print(subkey_cnt)
	print(values_cnt)
	print(lastwrite_time)

	print(22222222222222222222222222222)
	sd, err = await rs.GetKeySecurity(res, securityInformation=SECURITY_INFORMATION.OWNER|SECURITY_INFORMATION.DACL)
	if err is not None:
		print(err)
	print(sd)

	rx = res
	res2, err = await rs.CreateKey(res, "TEST")
	if err is not None:
		print(err)
	print(res)

	res, err = await rs.SetValue(res2, "TEST", REG_VAL_TYPE.SZ, "TESTING")
	if err is not None:
		print(err)
	print(res)


	#res, err = await rs.DeleteValue(res2, "TEST")
	#if err is not None:
	#	print(err)
	#print(res)

	res, err = await rs.DeleteKey(rx, "TEST")
	if err is not None:
		print(err)
	print(res)
	

	res, err = await rs.CloseKey(res)
	if err is not None:
		print(err)
	print(res)

if __name__ == '__main__':
	asyncio.run(amain())