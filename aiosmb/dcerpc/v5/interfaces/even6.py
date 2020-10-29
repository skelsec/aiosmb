
import asyncio
import os
import io

from aiosmb.dcerpc.v5.common.connection.smbdcefactory import SMBDCEFactory
from aiosmb.commons.utils.extb import pprint_exc
from aiosmb.commons.utils.decorators import red_gen, red, rr
from aiosmb.dcerpc.v5 import even6
from aiosmb.dcerpc.v5.interfaces.endpointmgr import EPM
from aiosmb.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_NONE, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, DCERPCException, RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_CONNECT
from aiosmb.dcerpc.v5.common.even6.binxml import Fragment
from aiosmb.dcerpc.v5.common.even6.resultset import RESULT_SET

### This does not work over SMB, only TCP/IP! Also, the RPC_C_AUTHN_LEVEL_PKT_PRIVACY must be set!!!
### 
###
###

class SMBEven6:
	def __init__(self, connection):
		self.connection = connection
		self.service_manager = None
		self.handles = {}
		
		self.dce = None
		
	async def __aenter__(self):
		return self
		
	async def __aexit__(self, exc_type, exc, traceback):
		await self.close()
		return True,None
	
	@red
	async def close(self):
		if self.dce:
			try:
				await self.dce.disconnect()
			except:
				pass
			return
		
		return True,None
	
	async def connect(self, open = True):
		try:
			epm = EPM(self.connection, protocol = 'ncacn_ip_tcp')
			_, err = await epm.connect()
			if err is not None:
				return False, err
			
			stringBinding, _ = await rr(epm.map(even6.MSRPC_UUID_EVEN6))
			self.dce = epm.get_connection_from_stringbinding(stringBinding)
			self.dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)

			_, err = await self.dce.connect()
			if err is not None:
				return False, err

			_, err = await self.dce.bind(even6.MSRPC_UUID_EVEN6)
			if err is not None:
				return False, err

			return True, None
		
		except Exception as e:
			return False, e

		finally:
			if epm is not None:
				await epm.disconnect()

	
	async def register_query(self, path, query = '*', flags = even6.EvtQueryChannelName | even6.EvtReadNewestToOldest):
		try:
			if path[-1] != '\x00':
				path += '\x00'
			if query[-1] != '\x00':
				query += '\x00'
			res, err = await even6.hEvtRpcRegisterLogQuery(self.dce, path, flags, query = query)
			if err is not None:
				raise err
			
			return res['Handle'], None
		
		except Exception as e:
			return None, e

	async def query_next(self, handle, num_req, timeout = 1000, as_xml = False):
		try:
			onetime = 10
			ranges = []
			if num_req <= onetime:
				ranges.append(num_req)
			else:
				i = 0
				while True:
					ranges.append(onetime)
					i += onetime
					if (i + onetime) < num_req:
						continue
					elif i == num_req:
						break
					else:
						ranges.append(num_req-i)
						break

			for i in ranges:
				res, err = await even6.hEvtRpcQueryNext(self.dce, handle, i, timeOutEnd=timeout)
				if err is not None:
					raise err
				
				pos = [x['Data'] for x in res['EventDataIndices']]
				size = [x['Data']for x in res['EventDataSizes']]
				buff = io.BytesIO(b''.join(res['ResultBuffer']))
				
				for p,s in zip(pos, size):
					buff.seek(p,io.SEEK_SET)
					if as_xml is False:
						yield RESULT_SET.from_bytes(buff.read(s)), None
					else:
						yield Fragment.from_bytes(RESULT_SET.from_bytes(buff.read(s)).eventData).to_xml() , None
			
		except Exception as e:
			yield None, e
			return

	async def list_channels(self):
		try:
			# doesnt work!
			res, err = await even6.hEvtRpcGetChannelList(self.dce)
			if err is not None:
				raise err

			return [x['Data'].replace('\x00','') for x in res['ChannelPaths']], None

		except Exception as e:
			return None, e

