
import asyncio
import os
from aiosmb.dcerpc.v5.common.connection.smbdcefactory import SMBDCEFactory
from aiosmb.commons.utils.extb import pprint_exc
from aiosmb.commons.utils.decorators import red_gen, red, rr
from aiosmb.dcerpc.v5 import even6
from aiosmb.dcerpc.v5.interfaces.endpointmgr import EPM
from aiosmb.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_NONE, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, DCERPCException, RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_CONNECT
from aiosmb.dcerpc.v5.common.binxml import Fragment

### This does not work over SMB, only TCP/IP! Also, the RPC_C_AUTHN_LEVEL_PKT_PRIVACY must be set!!!
### 
###
###
import io

class RESULT_SET:
	def __init__(self):
		self.totalSize = None
		self.headerSize = None
		self.eventOffset = None
		self.bookmarkOffset = None
		self.binXmlSize = None
		self.eventData = None
		self.numberOfSubqueryIDs = None
		self.subqueryIDs = None
		self.bookMarkData = None
	
	@staticmethod
	def from_bytes(data):
		return RESULT_SET.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		r = RESULT_SET()
		pos = buff.tell()
		r.totalSize = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		pos += r.totalSize
		r.headerSize = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		r.eventOffset = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		r.bookmarkOffset = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		r.binXmlSize = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		r.eventData = buff.read(r.binXmlSize)
		r.numberOfSubqueryIDs = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		r.subqueryIDs = buff.read(r.numberOfSubqueryIDs)
		r.bookMarkData = buff.read(pos - buff.tell())
		return r

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
		epm = EPM(self.connection, protocol = 'ncacn_ip_tcp')
		_, err = await epm.connect()
		if err is not None:
			raise err
		
		stringBinding, _ = await rr(epm.map(even6.MSRPC_UUID_EVEN6))
		self.dce = epm.get_connection_from_stringbinding(stringBinding)
		self.dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)

		_, err = await self.dce.connect()
		if err is not None:
			raise err

		_, err = await self.dce.bind(even6.MSRPC_UUID_EVEN6)
		if err is not None:
			return False, err
		
		#rpctransport = SMBDCEFactory(self.connection, filename=r'\eventlog')
		
		#self.dce = rpctransport.get_dce_rpc()
		#self.dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
		#_, err = await self.dce.connect()
		#if err is not None:
		#	return False, err
		#_, err = await self.dce.bind(even6.MSRPC_UUID_EVEN6)
		#if err is not None:
		#	return False, err

		return True,None

	
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
			res, err = await even6.hEvtRpcQueryNext(self.dce, handle, num_req, timeOutEnd=timeout)
			if err is not None:
				raise err
			
			pos = [x['Data'] for x in res['EventDataIndices']]
			size = [x['Data']for x in res['EventDataSizes']]
			buff = io.BytesIO(b''.join(res['ResultBuffer']))
			edata = []
			for p,s in zip(pos, size):
				buff.seek(p,io.SEEK_SET)
				if as_xml is False:
					edata.append(RESULT_SET.from_bytes(buff.read(s)))
				else:
					edata.append(Fragment.from_bytes(RESULT_SET.from_bytes(buff.read(s)).eventData).to_xml())
			
			return edata, None
		
		except Exception as e:
			return None, e

	async def list_channels(self):
		try:
			# doesnt work!
			res, err = await even6.hEvtRpcGetChannelList(self.dce)
			if err is not None:
				raise err

			return [x['Data'].replace('\x00','') for x in res['ChannelPaths']], None

		except Exception as e:
			return None, err


async def amain():
	import traceback
	from aiosmb.commons.connection.url import SMBConnectionURL
	from aiosmb.connection import SMBConnection

	url = ''
	su = SMBConnectionURL(url)
	conn = su.get_connection()

	_, err = await conn.login()
	if err is not None:
		print(err)
		return
	else:
		print('SMB Connected!')
	ei = SMBEven6(conn)
	_, err = await ei.connect()
	if err is not None:
		print(err)
		return
	print('DCE Connected!')
	
	
	sec_handle, err = await ei.register_query("Application")
	if err is not None:
		print(err)
	
	else:
		print(sec_handle)


	res, err = await ei.query_next(sec_handle, 1000, as_xml=True)
	if err is not None:
		print(err)
	
	else:
		print(res)

	await conn.disconnect()


	

if __name__ == '__main__':
	asyncio.run(amain())