
import asyncio
import os
from aiosmb.dcerpc.v5.common.connection.smbdcefactory import SMBDCEFactory
from aiosmb.dcerpc.v5 import tsch
from aiosmb.dcerpc.v5.dtypes import RPC_SID, DACL_SECURITY_INFORMATION
from aiosmb.wintypes.ntstatus import NTStatus
from aiosmb.dcerpc.v5.rpcrt import DCERPCException
from aiosmb import logger
import traceback
from aiosmb.commons.utils.extb import pprint_exc
from aiosmb.commons.utils.decorators import red_gen, red, rr
from aiosmb.dcerpc.v5.dtypes import NULL

from aiosmb.dcerpc.v5.interfaces.endpointmgr import EPM
from aiosmb.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_NONE, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, DCERPCException, RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_CONNECT


class SMBTSCH:
	def __init__(self, connection):
		self.connection = connection
		self.service_manager = None
		
		self.dce = None
		
	async def __aenter__(self):
		return self
		
	async def __aexit__(self, exc_type, exc, traceback):
		#await self.close()
		return True,None
	
	@red
	async def connect(self, open = True):
		rpctransport = SMBDCEFactory(self.connection, filename=r'\atsvc')
		
		self.dce = rpctransport.get_dce_rpc()
		self.dce.set_auth_level(RPC_C_AUTHN_LEVEL_CONNECT)
		await rr(self.dce.connect())
		await rr(self.dce.bind(tsch.MSRPC_UUID_TSCHS))

		return True,None	
	
	async def register_task(self, template, task_name = None, flags = tsch.TASK_CREATE, ssdl = NULL, logon_type = tsch.TASK_LOGON_NONE):
		if task_name is None:
			task_name = os.urandom(5).hex()
		if task_name[0] != '\\':
			task_name = '\\' + task_name

		if ssdl is None:
			ssdl = NULL

		res, err = await tsch.hSchRpcRegisterTask(self.dce, task_name, template, flags, ssdl, logon_type)
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
     </Exec>""".format(command)

		return ret