from typing import Tuple
import os
import asyncio
import traceback

from aiosmb import logger
from aiosmb.connection import SMBConnection
from aiosmb.dcerpc.v5.connection import DCERPC5Connection
from aiosmb.dcerpc.v5 import tsch
from aiosmb.dcerpc.v5.interfaces.endpointmgr import EPM
from aiosmb.dcerpc.v5.common.connection.smbdcefactory import SMBDCEFactory
from aiosmb.dcerpc.v5.dtypes import NULL
from aiosmb.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_NONE,\
	RPC_C_AUTHN_LEVEL_CONNECT,\
	RPC_C_AUTHN_LEVEL_CALL,\
	RPC_C_AUTHN_LEVEL_PKT,\
	RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,\
	RPC_C_AUTHN_LEVEL_PKT_PRIVACY,\
	DCERPCException, RPC_C_AUTHN_GSS_NEGOTIATE

from contextlib import asynccontextmanager

@asynccontextmanager
async def tschrpc_from_smb(connection, auth_level=None, open=True, perform_dummy=False):
    instance, err = await TSCHRPC.from_smbconnection(connection, auth_level=auth_level, open=open, perform_dummy=perform_dummy)
    if err:
        # Handle or raise the error as appropriate
        raise err
    try:
        yield instance
    finally:
        await instance.close()

class TSCHRPC:
	def __init__(self):
		self.service_pipename = r'\atsvc'
		self.service_uuid = tsch.MSRPC_UUID_TSCHS
		self.dce = None
		
	async def __aenter__(self):
		return self
		
	async def __aexit__(self, exc_type, exc, traceback):
		await self.close()
		return True,None
	
	async def close(self):
		try:
			if self.dce:
				try:
					await self.dce.disconnect()
				except:
					pass
				return
			
			return True,None
		except Exception as e:
			return None, e
	
	@staticmethod
	async def from_rpcconnection(connection:DCERPC5Connection, auth_level = None, open:bool = True, perform_dummy:bool = False):
		try:
			service = TSCHRPC()
			service.dce = connection
			
			service.dce.set_auth_level(auth_level)
			if auth_level is None:
				service.dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY) #secure default :P
			
			_, err = await service.dce.connect()
			if err is not None:
				raise err
			
			_, err = await service.dce.bind(service.service_uuid)
			if err is not None:
				raise err
				
			return service, None
		except Exception as e:
			return False, e
	
	@staticmethod
	async def from_smbconnection(connection:SMBConnection, auth_level = None, open:bool = True, perform_dummy:bool = False):
		"""
		Creates the connection to the service using an established SMBConnection.
		This connection will use the given SMBConnection as transport layer.
		"""
		try:
			if auth_level is None:
				auth_level = RPC_C_AUTHN_LEVEL_CONNECT
			rpctransport = SMBDCEFactory(connection, filename=TSCHRPC().service_pipename)		
			service, err = await TSCHRPC.from_rpcconnection(rpctransport.get_dce_rpc(), auth_level=auth_level, open=open, perform_dummy = perform_dummy)	
			if err is not None:
				raise err

			return service, None
		except Exception as e:
			return None, e
	
	async def register_task(self, template, task_name = None, flags = tsch.TASK_CREATE, sddl = NULL, logon_type = tsch.TASK_LOGON_NONE):
		if task_name is None:
			task_name = os.urandom(5).hex()
		if task_name[0] != '\\':
			task_name = '\\' + task_name

		if sddl is None:
			sddl = NULL

		res, err = await tsch.hSchRpcRegisterTask(self.dce, task_name, template, flags, sddl, logon_type)
		if err is not None:
			return None, err
		
		task_name = res['pActualPath']
		
		return task_name, err
	
	async def get_task_last_run_info(self, task_name):
		if task_name[0] != '\\':
			task_name = '\\' + task_name

		res, err = await tsch.hSchRpcGetLastRunInfo(self.dce, task_name)
		if err is not None:
			return None, err

		t = {
			'Year' : res['pLastRuntime']['wYear'],
			'Month' : res['pLastRuntime']['wMonth'],
			'DayOfWeek' : res['pLastRuntime']['wDayOfWeek'],
			'Day' : res['pLastRuntime']['wDay'],
			'Hour' : res['pLastRuntime']['wHour'],
			'Minute' : res['pLastRuntime']['wMinute'],
			'Second' : res['pLastRuntime']['wSecond'],
			'Miliseconds' : res['pLastRuntime']['wMilliseconds'],
			'LastReturnCode' : res['pLastRuntime']
		}
		return t, err

	async def delete_task(self, task_name):
		"""
		Deletes a task
		"""

		if task_name[0] != '\\':
			task_name = '\\' + task_name

		_, err = await tsch.hSchRpcDelete(self.dce, task_name)
		if err is not None:
			return False, err

		return True, err

	async def run_task(self, task_name):
		"""
		Starts a task
		"""
		if task_name[0] != '\\':
			task_name = '\\' + task_name
		
		_, err = await tsch.hSchRpcRun(self.dce, task_name)
		return True, err

	async def list_tasks(self, path = '\\'):
		"""
		Lists all available tasks on the remote machine
		"""
		try:
			resp, err = await tsch.hSchRpcEnumTasks(self.dce, path)
			if err is not None:
				yield None, err
				return
			
			for name in resp['pNames']:
				yield name['Data'].replace('\x00',''), None
		
		except Exception as e:
			yield None, e
			return
	
	async def get_task(self, task_name):
		"""
		Returns the task XML
		"""
		if task_name[0] != '\\':
			task_name = '\\' + task_name
		
		resp, err = await tsch.hSchRpcRetrieveTask(self.dce, task_name)
		if err is not None:
			return None, err
		
		return resp['pXml'], None

	async def get_task_sd(self, task_name):
		"""
		Returns the selected task's security descriptor
		"""
		if task_name[0] != '\\':
			task_name = '\\' + task_name
		
		resp, err = await tsch.hSchRpcGetSecurity(self.dce, task_name)
		if err is not None:
			return None, err
		
		return resp['sddl'], None
	
	async def list_folders(self, path = '\\'):
		"""
		Lists all available folders on the remote machine
		"""
		try:
			resp, err = await tsch.hSchRpcEnumFolders(self.dce, path)
			if err is not None:
				yield None, err
				return
			
			for name in resp['pNames']:
				yield name['Data'].replace('\x00',''), None
		
		except Exception as e:
			yield None, e
			return

	async def run_commands(self, commands, maxwait = 10):
		"""
		Executes a list of shell commands by scheduling a new task and starts it.
		At the end the new task will be deleted
		"""
		template = self.gen_xml(commands)
		task_name, err = await self.register_task(template)
		if err is not None:
			return None, err

		_, err = await self.run_task(task_name)
		if err is not None:
			return None, err


		while True:
			if maxwait < 0:
				return None, Exception('maxwait timeout!')
			
			res, err = await self.get_task_last_run_info(task_name)
			if err is not None:
				return None, err
			
			if res['Year'] != 0:
				break
			
			maxwait -= 3
			await asyncio.sleep(3)
			

		res, err = await self.delete_task(task_name)
		if err is not None:
			return None, err

		return True, None


	def gen_xml(self, commands):

		return """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
	<CalendarTrigger>
	  <StartBoundary>2015-07-15T20:35:13.2757294</StartBoundary>
	  <Enabled>true</Enabled>
	  <ScheduleByDay>
		<DaysInterval>1</DaysInterval>
	  </ScheduleByDay>
	</CalendarTrigger>
  </Triggers>
  <Principals>
	<Principal id="LocalSystem">
	  <UserId>S-1-5-18</UserId>
	  <RunLevel>HighestAvailable</RunLevel>
	</Principal>
  </Principals>
  <Settings>
	<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
	<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
	<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
	<AllowHardTerminate>true</AllowHardTerminate>
	<RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
	<IdleSettings>
	  <StopOnIdleEnd>true</StopOnIdleEnd>
	  <RestartOnIdle>false</RestartOnIdle>
	</IdleSettings>
	<AllowStartOnDemand>true</AllowStartOnDemand>
	<Enabled>true</Enabled>
	<Hidden>true</Hidden>
	<RunOnlyIfIdle>false</RunOnlyIfIdle>
	<WakeToRun>false</WakeToRun>
	<ExecutionTimeLimit>P3D</ExecutionTimeLimit>
	<Priority>7</Priority>
  </Settings>
  <Actions Context="LocalSystem">
	{}
  </Actions>
</Task>
""".format(self.gen_commands(commands))

	def gen_commands(self, commands):
		ret = ""
		for command in commands:
			ret += """
	 <Exec>
	  <Command>cmd.exe</Command>
	  <Arguments>/C {}</Arguments>
	 </Exec>""".format(self.xml_escape(command))

		return ret
	
	def xml_escape(self, data):
		replace_table = {
			 "&": "&amp;",
			 '"': "&quot;",
			 "'": "&apos;",
			 ">": "&gt;",
			 "<": "&lt;",
			 }
		return ''.join(replace_table.get(c, c) for c in data)
