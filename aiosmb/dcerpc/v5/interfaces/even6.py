
import asyncio
import os
from aiosmb.dcerpc.v5.common.connection.smbdcefactory import SMBDCEFactory
from aiosmb.commons.utils.extb import pprint_exc
from aiosmb.commons.utils.decorators import red_gen, red, rr
from aiosmb.dcerpc.v5 import even6
from aiosmb.dcerpc.v5.interfaces.endpointmgr import EPM
from aiosmb.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_NONE, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, DCERPCException, RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_CONNECT


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

	
	async def register_query(self, path, query = '*\x00', flags = even6.EvtQueryChannelName | even6.EvtReadNewestToOldest):
		try:
			res, err = await even6.hEvtRpcRegisterLogQuery(self.dce, path, flags, query = query)
			if err is not None:
				raise err
			
			return res['Handle'], None
		
		except Exception as e:
			return None, e

	async def query_next(self, handle, num_req, timeout = 1000):
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
				#edata.append(buff.read(size))
				edata.append(RESULT_SET.from_bytes(buff.read(s)))
			
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


from Evtx.BinaryParser import Block
from Evtx.Nodes import StreamStartNode
from Evtx.Nodes import TemplateNode

class ChunkTest(Block):
	
	def __init__(self, buf, offset):
		super(ChunkTest, self).__init__(buf, offset)
		self._strings = None
		self._templates = None

	def _load_templates(self):
		"""
		@return None
		"""
		if self._templates is None:
			self._templates = {}
		for i in range(32):
			ofs = self.unpack_dword(i * 4)
			print('ofs %s' % ofs)
			while ofs > 0:
				# unclear why these are found before the offset
				# this is a direct port from A.S.'s code
				token = self.unpack_byte(ofs - 10)
				pointer = self.unpack_dword(ofs - 4)
				if token != 0x0c or pointer != ofs:
					#logger.warning("Unexpected token encountered")
					ofs = 0
					continue
				template = self.add_template(ofs)
				ofs = template.next_offset()

	def add_template(self, offset, parent=None):
		"""
		@param offset An integer which contains the chunk-relative offset
		   to a template to load into this Chunk.
		@param parent (Optional) The parent of the newly created
		   TemplateNode instance. (Default: this chunk).
		@return Newly added TemplateNode instance.
		"""
		print('offs: %s' % offset)
		print('pl %s' % (self._offset + offset))
		if self._templates is None:
			self._load_templates()

		node = TemplateNode(self._buf, self._offset + offset,
							self, parent or self)
		self._templates[offset] = node
		return node

async def amain():
	#from evtx import PyEvtxParser
	from Evtx.Nodes import StreamStartNode
	#from Evtx.Evtx import BXmlNode
	
	from aiosmb.dcerpc.v5.interfaces.binxml import Fragment
	import traceback
	from aiosmb.commons.connection.url import SMBConnectionURL
	from aiosmb.connection import SMBConnection

	url = 'smb2+kerberos-password://TEST\\Administrator:QLFbT8zkiFGlJuf0B3Qq@win2019ad.test.corp?serverip=10.10.10.2&dc=10.10.10.2'
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
	
	
	#res, err = await ei.list_channels()
	#if err is not None:
	#	print(traceback.format_tb(err.__traceback__))
	#print(res)
	#return
	
	
	sec_handle, err = await ei.register_query("Security\x00")
	if err is not None:
		print(err)
	
	else:
		print(sec_handle)


	res, err = await ei.query_next(sec_handle, 1)
	if err is not None:
		print(err)
	
	else:
		for data in res:
			print(data.eventData)
			print(len(data.eventData))
			print(hex(len(data.eventData)))
			
			#tc = ChunkTest(data.eventData, 0)
			#t = data.eventData + b'\x00' * 100
			#buf = io.BytesIO(t)
			#chunk = StreamStartNode(data.eventData, 0, tc, None)
			
			#x = ChunkHeader(data.eventData, 0)
			#print(tc._templates)
			#print(str(chunk._children()))

			bx = Fragment.from_bytes(data.eventData)

			print(bx)
			#x = io.BytesIO(data.eventData)
			#parser = PyEvtxParser(x)
			#for record in parser.records_json():
			#	print(f'Event Record ID: {record["event_record_id"]}')
			#	print(f'Event Timestamp: {record["timestamp"]}')
			#	print(record['data'])
			#	print(f'------------------------------------------')
		#print(b''.join(res['ResultBuffer']))
		#x = RESULT_SET.from_bytes(b''.join(res['ResultBuffer']))
		#print(x.eventData)
		#print(res.dump())

	await conn.disconnect()



if __name__ == '__main__':
	asyncio.run(amain())