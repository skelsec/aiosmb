import enum
from aiosmb.dcerpc.v5.scmr import QUERY_SERVICE_CONFIGW

# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/97200665-5631-42ea-9917-6f9b41f02391

class ServiceStatus(enum.Enum):
	CONTINUE_PENDING = 0x00000005
	PAUSE_PENDING = 0x00000006
	PAUSED = 0x00000007
	RUNNING = 0x00000004
	START_PENDING = 0x00000002
	STOP_PENDING = 0x00000003
	STOPPED = 0x00000001
	DISABLED = 'DISABLED'
	UNKNOWN = 0

class ServiceType(enum.Enum):
	UNKNOWN = 0x00000000 #The service type cannot be specified.
	KERNEL_DRIVER = 0x00000001 #A driver service. These are services that manage devices on the system.
	FILE_SYSTEM_DRIVER = 0x00000002 #A file system driver service. These are services that manage file systems on the system.
	WIN32_OWN_PROCESS = 0x00000010 #A service that runs in its own process.
	WIN32_SHARE_PROCESS  = 0x00000020 #A service that shares a process with other services.
	INTERACTIVE_PROCESS = 0x00000100
	OWN_PROCESS_INTERACTIVE = 0x00000110
	SHARE_PROCESS_INTERACTIVE = 0x00000120
	USER_OWN_PROCESS = 0x00000050
	USER_OWN_PROCESS_INSTANCE = 0x000000d0
	USER_SHARE_PROCESS = 0x00000060
	USER_SHARE_PROCESS_INSTANCE = 0x000000e0
	PACKAGE_OWN_PROCESS = 0x00000210
	PACKAGE_SHARE_PROCESS = 0x00000220

class ServiceStartType(enum.Enum):
	BOOT_START = 0x00000000 #A device driver started by the system loader. This value is valid only for driver services.
	SYSTEM_START = 0x00000001 #A device driver started by the IoInitSystem function. This value is valid only for driver services.
	AUTO_START = 0x00000002 #A service started automatically by the service control manager during system startup.
	DEMAND_START = 0x00000003 #A service started by the service control manager when a process calls the StartService function.
	DISABLED = 0x00000004 #A service that cannot be started. Attempts to start the service result in the error code ERROR_SERVICE_DISABLED.

class ServiceErrorControl(enum.Enum):
	IGNORE = 0x00000000 #The startup program ignores the error and continues the startup operation.
	NORMAL = 0x00000001 #The startup program logs the error in the event log but continues the startup operation.
	SEVERE = 0x00000002 #The startup program logs the error in the event log. If the last-known-good configuration is being started, the startup operation continues. Otherwise, the system is restarted with the last-known-good configuration.
	CRITICAL = 0x00000003 #The startup program logs the error in the event log, if possible. If the last-known-good configuration is being started, the startup operation fails. Otherwise, the system is restarted with the last-known good configuration.

class SMBService:
	def __init__(self,name = None, display_name = None, status = None):
		self.name:str = name
		self.display_name:str = display_name
		self.status:ServiceStatus = status
		self.type:ServiceType = ServiceType.UNKNOWN
		self.starttype:ServiceStartType = None
		self.errorcontrol:ServiceErrorControl = None
		self.binarypath:str = None
		self.loadordergroup:str = None
		self.tagid:int = None
		self.dependencies:str = None
	
	@staticmethod
	def from_query_result(ans:QUERY_SERVICE_CONFIGW, name:str = None):
		service = SMBService()
		tname = ans['lpServiceConfig']['lpServiceStartName'][:-1]
		if tname is None or tname == '':
			if name is not None:
				tname = name
		service.name = tname
		service.display_name = ans['lpServiceConfig']['lpDisplayName'][:-1]
		try:
			# there are other undocumented types... thx microsoft!
			if ans['lpServiceConfig']['dwServiceType'] is not None:
				service.type = ServiceType(ans['lpServiceConfig']['dwServiceType'])
		except:
			pass
		if ans['lpServiceConfig']['dwStartType'] is not None:
			service.starttype = ServiceStartType(ans['lpServiceConfig']['dwStartType'])
		if ans['lpServiceConfig']['dwErrorControl'] is not None:
			service.errorcontrol = ServiceErrorControl(ans['lpServiceConfig']['dwErrorControl'])
		service.binarypath = ans['lpServiceConfig']['lpBinaryPathName'][:-1]
		service.loadordergroup = ans['lpServiceConfig']['lpLoadOrderGroup'][:-1]
		service.tagid = ans['lpServiceConfig']['dwTagId']
		service.dependencies = ans['lpServiceConfig']['lpDependencies'][:-1]
		return service
	
	def get_stauts_line(self):
		return '%s - %s - %s' % (self.name, self.display_name, self.status.name)

	def __str__(self):
		t = ''
		for k in self.__dict__:
			if self.__dict__[k] is None:
				continue
			t += '%s: %s\r\n' % (k, self.__dict__[k])
		return t