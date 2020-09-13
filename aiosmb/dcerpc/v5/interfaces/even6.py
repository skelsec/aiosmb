
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
	#from aiosmb.dcerpc.v5.interfaces.binxml import Fragment
	#data = bytes.fromhex('0f0101000c0021cdb848318cb15532732e077b9eaffedd0400000f010100411300d1040000ba0c05004500760065006e00740000007f00000006bc0f050078006d006c006e00730000000501350068007400740070003a002f002f0073006300680065006d00610073002e006d006900630072006f0073006f00660074002e0063006f006d002f00770069006e002f0032003000300034002f00300038002f006500760065006e00740073002f006500760065006e0074000201ffff310400006f540600530079007300740065006d0000000241ffff3a010000f17b0800500072006f007600690064006500720000001f010000464b9504004e0061006d006500000005011e004d006900630072006f0073006f00660074002d00570069006e0064006f00770073002d00530065006300750072006900740079002d00530050005000462915040047007500690064000000050126007b00450032003300420033003300420030002d0043003800430039002d0034003700320043002d0041003500460039002d004600320042004400460045004100300046003100350036007d000660d60f004500760065006e00740053006f0075007200630065004e0061006d00650000000501240053006f006600740077006100720065002000500072006f00740065006300740069006f006e00200050006c006100740066006f0072006d0020005300650072007600690063006500034103003d000000f56107004500760065006e0074004900440000001f0000000629da0a005100750061006c0069006600690065007200730000000e040006020e03000604010b001a00000018090700560065007200730069006f006e000000020e0b0004040100001600000064ce05004c006500760065006c000000020e0000040401020014000000457b04005400610073006b000000020e0200060401010018000000ae1e06004f00700063006f00640065000000020e010004040105001c0000006acf08004b006500790077006f007200640073000000020e0500150441ffff400000003b8e0b00540069006d006500430072006500610074006500640000001f000000063c7b0a00530079007300740065006d00540069006d00650000000e06001103010a002600000046030d004500760065006e0074005200650063006f0072006400490044000000020e0a000a0441ffff6d000000a2f20b0043006f007200720065006c006100740069006f006e0000004c000000460af10a00410063007400690076006900740079004900440000000e07000f0635c51100520065006c006100740065006400410063007400690076006900740079004900440000000e12000f0341ffff55000000b8b5090045007800650063007500740069006f006e00000038000000460ad70900500072006f0063006500730073004900440000000e08000806853908005400680072006500610064004900440000000e0900080301ffff30000000836107004300680061006e006e0065006c0000000205010b004100700070006c00690063006100740069006f006e000401ffff420000003b6e080043006f006d007000750074006500720000000205011300570049004e003200300031003900410044002e0074006500730074002e0063006f00720070000441ffff32000000a02e08005300650063007500720069007400790000001700000006664c060055007300650072004900440000000e0c001303040e1300210400140000000100040001000400020006000200060002000600080015000800110000000000040008000400080008000a0001000400000000000000000000000000000000000000000000000000000000008f002100040000000a4000c000000000000080000cd6ec197389d60100000000000000006b71020000000000000f0101000c0077d82943d5d82d51ec99201a0fd92fc7600000000f01010001ffff54000000448209004500760065006e0074004400610074006100000002010000140000008a6f040044006100740061000000020e000081040102001800000021b80600420069006e006100720079000000020e02000e04040003000000000000000400080000000000000000000000')
	#bx = Fragment.from_bytes(data)

	asyncio.run(amain())