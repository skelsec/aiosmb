
import logging
from aiosmb import logger

#from aiosmb.dtyp.constrcuted_security.guid import GUID

from aiosmb.dcerpc.v5.dtypes import NULL
from aiosmb.dcerpc.v5.uuid import string_to_bin
from aiosmb.dcerpc.v5.transport.smbtransport import SMBTransport
from aiosmb.dcerpc.v5.transport.factory import DCERPCTransportFactory
from aiosmb.dcerpc.v5 import epm, drsuapi
from aiosmb.dcerpc.v5.interfaces.servicemanager import *
from aiosmb.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY, DCERPCException, RPC_C_AUTHN_GSS_NEGOTIATE
		
class SMBDRSUAPI:
	def __init__(self, connection, domainname = None):
		self.connection = connection	
		self.domainname = domainname
		
		self.dce = None
		self.handle = None
		
		self.__NtdsDsaObjectGuid = None
		self.__ppartialAttrSet = None
		
		self.ATTRTYP_TO_ATTID = {
				'userPrincipalName': '1.2.840.113556.1.4.656',
				'sAMAccountName': '1.2.840.113556.1.4.221',
				'unicodePwd': '1.2.840.113556.1.4.90',
				'dBCSPwd': '1.2.840.113556.1.4.55',
				'ntPwdHistory': '1.2.840.113556.1.4.94',
				'lmPwdHistory': '1.2.840.113556.1.4.160',
				'supplementalCredentials': '1.2.840.113556.1.4.125',
				'objectSid': '1.2.840.113556.1.4.146',
				'pwdLastSet': '1.2.840.113556.1.4.96',
				'userAccountControl':'1.2.840.113556.1.4.8',
			}
			
		self.NAME_TO_ATTRTYP = {
			'userPrincipalName': 0x90290,
			'sAMAccountName': 0x900DD,
			'unicodePwd': 0x9005A,
			'dBCSPwd': 0x90037,
			'ntPwdHistory': 0x9005E,
			'lmPwdHistory': 0x900A0,
			'supplementalCredentials': 0x9007D,
			'objectSid': 0x90092,
			'userAccountControl':0x90008,
		}
		
	async def __aenter__(self):
		return self
		
	async def __aexit__(self, exc_type, exc, traceback):
		await self.close()
		
	async def connect(self, open = False):
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
		resp = await drsuapi.hDRSDomainControllerInfo(self.dce, self.handle, self.domainname, 2)
		if logger.level == logging.DEBUG:
			logger.debug('DRSDomainControllerInfo() answer')
			resp.dump()

		if resp['pmsgOut']['V2']['cItems'] > 0:
			self.__NtdsDsaObjectGuid = resp['pmsgOut']['V2']['rItems'][0]['NtdsDsaObjectGuid']
		else:
			logger.error("Couldn't get DC info for domain %s" % self.domainname)
			raise Exception('Fatal, aborting!')
	
	async def get_user_secrets(self, username):
		ra = {
			'userPrincipalName': '1.2.840.113556.1.4.656',
			'sAMAccountName': '1.2.840.113556.1.4.221',
			'unicodePwd': '1.2.840.113556.1.4.90',
			'dBCSPwd': '1.2.840.113556.1.4.55',
			'ntPwdHistory': '1.2.840.113556.1.4.94',
			'lmPwdHistory': '1.2.840.113556.1.4.160',
			'supplementalCredentials': '1.2.840.113556.1.4.125',
			'objectSid': '1.2.840.113556.1.4.146',
			'pwdLastSet': '1.2.840.113556.1.4.96',
			'userAccountControl':'1.2.840.113556.1.4.8'
		}
		formatOffered = drsuapi.DS_NT4_ACCOUNT_NAME_SANS_DOMAIN
		
		crackedName = await self.DRSCrackNames(
			formatOffered,
			drsuapi.DS_NAME_FORMAT.DS_UNIQUE_ID_NAME,
			name=username
		)
		print(crackedName.dump())
		
		###### TODO: CHECKS HERE
		
		#guid = GUID.from_string(crackedName['pmsgOut']['V1']['pResult']['rItems'][0]['pName'][:-1][1:-1])
		guid = crackedName['pmsgOut']['V1']['pResult']['rItems'][0]['pName'][:-1][1:-1]
		input(guid)
		
		userRecord = await self.DRSGetNCChanges(guid, ra)
		
		replyVersion = 'V%d' % userRecord['pdwOutVersion']
		if userRecord['pmsgOut'][replyVersion]['cNumObjects'] == 0:
			raise Exception('DRSGetNCChanges didn\'t return any object!')
		
		#print(userRecord.dump())
		#print(userRecord['pmsgOut'][replyVersion]['PrefixTableSrc']['pPrefixEntry'])
		
		record = userRecord
		prefixTable = userRecord['pmsgOut'][replyVersion]['PrefixTableSrc']['pPrefixEntry']
		##### decryption!
		logger.debug('Decrypting hash for user: %s' % record['pmsgOut'][replyVersion]['pNC']['StringName'][:-1])
		
		domain = None
		LMHistory = []
		NTHistory = []
		
		NTHash = None
		LMHash = None
		userName = None
		objectSid = None
		pwdLastSet = None
		userAccountStatus = None

		rid = int.from_bytes(record['pmsgOut'][replyVersion]['pObjects']['Entinf']['pName']['Sid'][-4:], 'little', signed = False)
		
		for attr in record['pmsgOut'][replyVersion]['pObjects']['Entinf']['AttrBlock']['pAttr']:
		
			try:
				attId = drsuapi.OidFromAttid(prefixTable, attr['attrTyp'])
				LOOKUP_TABLE = self.ATTRTYP_TO_ATTID
			except Exception as e:
				logger.error('Failed to execute OidFromAttid with error %s, fallbacking to fixed table' % e)
				logger.error('Exception', exc_info=True)
				input()
				# Fallbacking to fixed table and hope for the best
				attId = attr['attrTyp']
				LOOKUP_TABLE = self.NAME_TO_ATTRTYP
				
			if attId == LOOKUP_TABLE['dBCSPwd']:
				if attr['AttrVal']['valCount'] > 0:
					encrypteddBCSPwd = b''.join(attr['AttrVal']['pAVal'][0]['pVal'])
					encryptedLMHash = drsuapi.DecryptAttributeValue(self.dce.get_session_key(), encrypteddBCSPwd)
					LMHash = drsuapi.removeDESLayer(encryptedLMHash, rid)
				else:
					LMHash = bytes.fromhex('aad3b435b51404eeaad3b435b51404ee')
					
			elif attId == LOOKUP_TABLE['unicodePwd']:
				if attr['AttrVal']['valCount'] > 0:
					encryptedUnicodePwd = b''.join(attr['AttrVal']['pAVal'][0]['pVal'])
					encryptedNTHash = drsuapi.DecryptAttributeValue(self.dce.get_session_key(), encryptedUnicodePwd)
					NTHash = drsuapi.removeDESLayer(encryptedNTHash, rid)
				else:
					NTHash = bytes.fromhex('31d6cfe0d16ae931b73c59d7e0c089c0')
					
			elif attId == LOOKUP_TABLE['userPrincipalName']:
				if attr['AttrVal']['valCount'] > 0:
					try:
						domain = b''.join(attr['AttrVal']['pAVal'][0]['pVal']).decode('utf-16le').split('@')[-1]
					except:
						domain = None
					else:
						domain = None
						
			elif attId == LOOKUP_TABLE['sAMAccountName']:
				if attr['AttrVal']['valCount'] > 0:
					try:
						userName = b''.join(attr['AttrVal']['pAVal'][0]['pVal']).decode('utf-16le')
					except:
						logger.error('Cannot get sAMAccountName for %s' % record['pmsgOut'][replyVersion]['pNC']['StringName'][:-1])
						userName = 'unknown'
					else:
						logger.error('Cannot get sAMAccountName for %s' % record['pmsgOut'][replyVersion]['pNC']['StringName'][:-1])
						userName = 'unknown'
						
			elif attId == LOOKUP_TABLE['objectSid']:
				if attr['AttrVal']['valCount'] > 0:
					objectSid = b''.join(attr['AttrVal']['pAVal'][0]['pVal'])
				else:
					logger.error('Cannot get objectSid for %s' % record['pmsgOut'][replyVersion]['pNC']['StringName'][:-1])
					objectSid = rid
			elif attId == LOOKUP_TABLE['pwdLastSet']:
				if attr['AttrVal']['valCount'] > 0:
					try:
						pwdLastSet = self.__fileTimeToDateTime(unpack('<Q', b''.join(attr['AttrVal']['pAVal'][0]['pVal']))[0])
					except:
						logger.error('Cannot get pwdLastSet for %s' % record['pmsgOut'][replyVersion]['pNC']['StringName'][:-1])
						pwdLastSet = 'N/A'
						
			elif attId == LOOKUP_TABLE['userAccountControl']:
				if attr['AttrVal']['valCount'] > 0:
					userAccountStatus = int.from_bytes(b''.join(attr['AttrVal']['pAVal'][0]['pVal']), 'little', signed = False)
				else:
					userAccountStatus = None
					
			if attId == LOOKUP_TABLE['lmPwdHistory']:
				if attr['AttrVal']['valCount'] > 0:
					encryptedLMHistory = b''.join(attr['AttrVal']['pAVal'][0]['pVal'])
					tmpLMHistory = drsuapi.DecryptAttributeValue(self.dce.get_session_key(), encryptedLMHistory)
					for i in range(0, len(tmpLMHistory) // 16):
						LMHashHistory = drsuapi.removeDESLayer(tmpLMHistory[i * 16:(i + 1) * 16], rid)
						LMHistory.append(LMHashHistory)
				else:
					logger.debug('No lmPwdHistory for user %s' % record['pmsgOut'][replyVersion]['pNC']['StringName'][:-1])
			elif attId == LOOKUP_TABLE['ntPwdHistory']:
				if attr['AttrVal']['valCount'] > 0:
					encryptedNTHistory = b''.join(attr['AttrVal']['pAVal'][0]['pVal'])
					tmpNTHistory = drsuapi.DecryptAttributeValue(self.dce.get_session_key(), encryptedNTHistory)
					for i in range(0, len(tmpNTHistory) // 16):
						NTHashHistory = drsuapi.removeDESLayer(tmpNTHistory[i * 16:(i + 1) * 16], rid)
						NTHistory.append(NTHashHistory)
				else:
					logger.debug('No ntPwdHistory for user %s' % record['pmsgOut'][replyVersion]['pNC']['StringName'][:-1])
					
			####continue writing this
			
			
			
		print('NT hash %s' % NTHash)
		print('LM hash %s' % LMHash)
		print('LM hash %s' % LMHistory)	
		print('NT hash %s' % NTHistory)	
		input()
			
		
	async def DRSCrackNames(self, formatOffered=drsuapi.DS_NAME_FORMAT.DS_DISPLAY_NAME, formatDesired=drsuapi.DS_NAME_FORMAT.DS_FQDN_1779_NAME, name=''):
		if self.handle is None:
			await self.open()

		logger.debug('Calling DRSCrackNames for %s ' % name)
		resp = await drsuapi.hDRSCrackNames(self.dce, self.handle, 0, formatOffered, formatDesired, (name,))
		return resp
		
	async def DRSGetNCChanges(self, guid, req_attributes = {}):
		if self.handle is None:
			self.open()

		logger.debug('Calling DRSGetNCChanges for %s ' % guid)
		request = drsuapi.DRSGetNCChanges()
		request['hDrs'] = self.handle
		request['dwInVersion'] = 8

		request['pmsgIn']['tag'] = 8
		request['pmsgIn']['V8']['uuidDsaObjDest'] = self.__NtdsDsaObjectGuid
		request['pmsgIn']['V8']['uuidInvocIdSrc'] = self.__NtdsDsaObjectGuid

		dsName = drsuapi.DSNAME()
		dsName['SidLen'] = 0
		dsName['Guid'] = string_to_bin(guid)#guid.to_bytes()
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
			self.__ppartialAttrSet['cAttrs'] = len(req_attributes)
			for attId in list(req_attributes.values()):
				self.__ppartialAttrSet['rgPartialAttr'].append(drsuapi.MakeAttid(self.__prefixTable , attId))
		request['pmsgIn']['V8']['pPartialAttrSet'] = self.__ppartialAttrSet
		request['pmsgIn']['V8']['PrefixTableDest']['PrefixCount'] = len(self.__prefixTable)
		request['pmsgIn']['V8']['PrefixTableDest']['pPrefixEntry'] = self.__prefixTable
		request['pmsgIn']['V8']['pPartialAttrSetEx1'] = NULL

		return await self.dce.request(request)
		
	async def close(self):
		raise Exception('Not implemented!')