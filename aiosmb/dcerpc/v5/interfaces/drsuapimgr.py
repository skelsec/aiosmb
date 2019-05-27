
import logging
from aiosmb import logger
from aiosmb.dcerpc.v5.transport.smbtransport import SMBTransport
from aiosmb.dcerpc.v5.transport.factory import DCERPCTransportFactory
from aiosmb.dcerpc.v5 import epm, drsuapi
from aiosmb.dcerpc.v5.interfaces.servicemanager import *
from aiosmb.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY, DCERPCException, RPC_C_AUTHN_GSS_NEGOTIATE
		
class SMBDRSUAPI:
	def __init__(self, connection):
		self.connection = connection	
		self.dce = None
		self.handle = None
		
		self.__NtdsDsaObjectGuid = None
		
	async def __aenter__(self):
		return self
		
	async def __aexit__(self, exc_type, exc, traceback):
		await self.close()
		
	async def connect(self, open = False):
		####### IMPORTANT!!!
		#### FIX: domain name must be set!!!
		domainname = 'TEST.corp'
	
	
		stringBinding = await epm.hept_map(self.connection, drsuapi.MSRPC_UUID_DRSUAPI, protocol='ncacn_ip_tcp')
		print(stringBinding)
		rpc = DCERPCTransportFactory(stringBinding, self.connection)
		
		rpc.setRemoteHost(self.connection.target.get_ip())
		rpc.setRemoteName(self.connection.target.get_ip())
		self.dce = rpc.get_dce_rpc()
		self.dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
		#if self.__doKerberos:
		#	self.dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
		await self.dce.connect()
		print('Connected!')
		
		if open == True:
			await self.open()
			
	async def open(self):
		if not self.dce:
			await self.connect()
		
		print('WOW!')
		await self.dce.bind(drsuapi.MSRPC_UUID_DRSUAPI)
		print('WOW2!')
		
		#if self.__domainName is None:
			# Get domain name from credentials cached
		#	self.__domainName = rpc.get_credentials()[2]
			
		request = drsuapi.DRSBind()
		request['puuidClientDsa'] = drsuapi.NTDSAPI_CLIENT_GUID
		drs = drsuapi.DRS_EXTENSIONS_INT()
		drs['cb'] = len(drs) #- 4
		drs['dwFlags'] = drsuapi.DRS_EXT_GETCHGREQ_V6 | drsuapi.DRS_EXT_GETCHGREPLY_V6 | drsuapi.DRS_EXT_GETCHGREQ_V8 | \
						 drsuapi.DRS_EXT_STRONG_ENCRYPTION
		drs['SiteObjGuid'] = drsuapi.NULLGUID
		drs['Pid'] = 0
		drs['dwReplEpoch'] = 0
		drs['dwFlagsExt'] = 0
		drs['ConfigObjGUID'] = drsuapi.NULLGUID
		# I'm uber potential (c) Ben
		drs['dwExtCaps'] = 0xffffffff
		request['pextClient']['cb'] = len(drs)
		request['pextClient']['rgb'] = list(drs.getData())
		resp = await self.dce.request(request)
		
		print(resp.dump())
		
		# Let's dig into the answer to check the dwReplEpoch. This field should match the one we send as part of
		# DRSBind's DRS_EXTENSIONS_INT(). If not, it will fail later when trying to sync data.
		drsExtensionsInt = drsuapi.DRS_EXTENSIONS_INT()

		# If dwExtCaps is not included in the answer, let's just add it so we can unpack DRS_EXTENSIONS_INT right.
		ppextServer = b''.join(resp['ppextServer']['rgb']) + b'\x00' * (
		len(drsuapi.DRS_EXTENSIONS_INT()) - resp['ppextServer']['cb'])
		drsExtensionsInt.fromString(ppextServer)

		if drsExtensionsInt['dwReplEpoch'] != 0:
			# Different epoch, we have to call DRSBind again
			if logger.level == logging.DEBUG:
				logger.debug("DC's dwReplEpoch != 0, setting it to %d and calling DRSBind again" % drsExtensionsInt[
					'dwReplEpoch'])
			drs['dwReplEpoch'] = drsExtensionsInt['dwReplEpoch']
			request['pextClient']['cb'] = len(drs)
			request['pextClient']['rgb'] = list(drs.getData())
			resp = await self.dce.request(request)

		self.handle = resp['phDrs']

		# Now let's get the NtdsDsaObjectGuid UUID to use when querying NCChanges
		resp = await drsuapi.hDRSDomainControllerInfo(self.dce, self.handle, domainname, 2)
		if logger.level == logging.DEBUG:
			logger.debug('DRSDomainControllerInfo() answer')
			resp.dump()

		if resp['pmsgOut']['V2']['cItems'] > 0:
			self.__NtdsDsaObjectGuid = resp['pmsgOut']['V2']['rItems'][0]['NtdsDsaObjectGuid']
		else:
			logger.error("Couldn't get DC info for domain %s" % domainname)
			raise Exception('Fatal, aborting!')
	
			
	async def DRSCrackNames(self, formatOffered=drsuapi.DS_NAME_FORMAT.DS_DISPLAY_NAME,
					  formatDesired=drsuapi.DS_NAME_FORMAT.DS_FQDN_1779_NAME, name=''):
		if self.handle is None:
			await self.open()

		logger.debug('Calling DRSCrackNames for %s ' % name)
		resp = await drsuapi.hDRSCrackNames(self.dce, self.handle, 0, formatOffered, formatDesired, (name,))
		return resp
		
	async def DRSGetNCChanges(self, userEntry):
		if self.handle is None:
			self.open()

		logger.debug('Calling DRSGetNCChanges for %s ' % userEntry)
		request = drsuapi.DRSGetNCChanges()
		request['hDrs'] = self.__hDrs
		request['dwInVersion'] = 8

		request['pmsgIn']['tag'] = 8
		request['pmsgIn']['V8']['uuidDsaObjDest'] = self.__NtdsDsaObjectGuid
		request['pmsgIn']['V8']['uuidInvocIdSrc'] = self.__NtdsDsaObjectGuid

		dsName = drsuapi.DSNAME()
		dsName['SidLen'] = 0
		dsName['Guid'] = string_to_bin(userEntry[1:-1])
		dsName['Sid'] = ''
		dsName['NameLen'] = 0
		dsName['StringName'] = ('\x00')

		dsName['structLen'] = len(dsName.getData())

		request['pmsgIn']['V8']['pNC'] = dsName

		request['pmsgIn']['V8']['usnvecFrom']['usnHighObjUpdate'] = 0
		request['pmsgIn']['V8']['usnvecFrom']['usnHighPropUpdate'] = 0

		request['pmsgIn']['V8']['pUpToDateVecDest'] = NULL

		request['pmsgIn']['V8']['ulFlags'] =  drsuapi.DRS_INIT_SYNC | drsuapi.DRS_WRIT_REP
		request['pmsgIn']['V8']['cMaxObjects'] = 1
		request['pmsgIn']['V8']['cMaxBytes'] = 0
		request['pmsgIn']['V8']['ulExtendedOp'] = drsuapi.EXOP_REPL_OBJ
		if self.__ppartialAttrSet is None:
			self.__prefixTable = []
			self.__ppartialAttrSet = drsuapi.PARTIAL_ATTR_VECTOR_V1_EXT()
			self.__ppartialAttrSet['dwVersion'] = 1
			self.__ppartialAttrSet['cAttrs'] = len(NTDSHashes.ATTRTYP_TO_ATTID)
			for attId in list(NTDSHashes.ATTRTYP_TO_ATTID.values()):
				self.__ppartialAttrSet['rgPartialAttr'].append(drsuapi.MakeAttid(self.__prefixTable , attId))
		request['pmsgIn']['V8']['pPartialAttrSet'] = self.__ppartialAttrSet
		request['pmsgIn']['V8']['PrefixTableDest']['PrefixCount'] = len(self.__prefixTable)
		request['pmsgIn']['V8']['PrefixTableDest']['pPrefixEntry'] = self.__prefixTable
		request['pmsgIn']['V8']['pPartialAttrSetEx1'] = NULL

		return self.dce.request(request)
		
	async def close(self):
		raise Exception('Not implemented!')