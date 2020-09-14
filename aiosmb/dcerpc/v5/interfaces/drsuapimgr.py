
import logging
from aiosmb import logger
import traceback

#from aiosmb.dtyp.constrcuted_security.guid import GUID
from aiosmb.dcerpc.v5.common.secrets import SMBUserSecrets
from aiosmb.wintypes.dtyp.structures.filetime import FILETIME
from aiosmb.wintypes.dtyp.constrcuted_security.sid import SID
from aiosmb.dcerpc.v5.dtypes import NULL
from aiosmb.dcerpc.v5.uuid import string_to_bin
from aiosmb.dcerpc.v5 import drsuapi, samr
from aiosmb.dcerpc.v5.interfaces.endpointmgr import EPM
from aiosmb.dcerpc.v5.interfaces.servicemanager import *
from aiosmb.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, DCERPCException, RPC_C_AUTHN_GSS_NEGOTIATE

from aiosmb.commons.utils.decorators import red, rr

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
		
		self.KERBEROS_TYPE = {
			1:'dec-cbc-crc',
			3:'des-cbc-md5',
			17:'aes128-cts-hmac-sha1-96',
			18:'aes256-cts-hmac-sha1-96',
			0xffffff74:'rc4_hmac',
		}
		
	async def __aenter__(self):
		return self
	
	@red
	async def __aexit__(self, exc_type, exc, traceback):
		await self.close()
		return True,None
		
	
	async def connect(self, open = False):
		try:
			epm = EPM(self.connection, protocol = 'ncacn_ip_tcp')
			_, err = await epm.connect()
			if err is not None:
				raise err
			stringBinding, _ = await rr(epm.map(drsuapi.MSRPC_UUID_DRSUAPI))
			self.dce = epm.get_connection_from_stringbinding(stringBinding)

			#the line below must be set!
			self.dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)

			_, err = await self.dce.connect()
			if err is not None:
				raise err

			
			if open == True:
				_, err = await self.open()
				if err is not None:
					raise err
			return True, None
		except Exception as e:
			return False, e
		finally:
			if epm is not None:
				await epm.disconnect()
		
	async def open(self):
		try:
			if not self.dce:
				await rr(self.connect())
			
			await rr(self.dce.bind(drsuapi.MSRPC_UUID_DRSUAPI))
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
			resp,_ = await rr(self.dce.request(request))
			
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
				resp,_ = await rr(self.dce.request(request))

			self.handle = resp['phDrs']

			# Now let's get the NtdsDsaObjectGuid UUID to use when querying NCChanges
			resp, _ = await rr(drsuapi.hDRSDomainControllerInfo(self.dce, self.handle, self.domainname, 2))
			if logger.level == logging.DEBUG:
				logger.debug('DRSDomainControllerInfo() answer %s' % resp.dump())

			if resp['pmsgOut']['V2']['cItems'] > 0:
				self.__NtdsDsaObjectGuid = resp['pmsgOut']['V2']['rItems'][0]['NtdsDsaObjectGuid']
			else:
				logger.debug("Couldn't get DC info for domain %s" % self.domainname)
				raise Exception('Fatal, aborting!')

			return True,None
		except Exception as e:
			return None, e
	
	async def get_user_secrets(self, username):
		try:
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
			
			crackedName, _ = await rr(
				self.DRSCrackNames(
					formatOffered,
					drsuapi.DS_NAME_FORMAT.DS_UNIQUE_ID_NAME,
					name=username
				)
			)
			
			###### TODO: CHECKS HERE
			
			#guid = GUID.from_string(crackedName['pmsgOut']['V1']['pResult']['rItems'][0]['pName'][:-1][1:-1])
			guid = crackedName['pmsgOut']['V1']['pResult']['rItems'][0]['pName'][:-1][1:-1]
			
			userRecord, err = await self.DRSGetNCChanges(guid, ra)
			if err is not None:
				return None, err
			
			replyVersion = 'V%d' % userRecord['pdwOutVersion']
			if userRecord['pmsgOut'][replyVersion]['cNumObjects'] == 0:
				raise Exception('DRSGetNCChanges didn\'t return any object!')
			
			#print(userRecord.dump())
			#print(userRecord['pmsgOut'][replyVersion]['PrefixTableSrc']['pPrefixEntry'])
			
			record = userRecord
			prefixTable = userRecord['pmsgOut'][replyVersion]['PrefixTableSrc']['pPrefixEntry']
			##### decryption!
			logger.debug('Decrypting hash for user: %s' % record['pmsgOut'][replyVersion]['pNC']['StringName'][:-1])
			
			us = SMBUserSecrets()
			user_properties = None

			rid = int.from_bytes(record['pmsgOut'][replyVersion]['pObjects']['Entinf']['pName']['Sid'][-4:], 'little', signed = False)
			
			for attr in record['pmsgOut'][replyVersion]['pObjects']['Entinf']['AttrBlock']['pAttr']:
			
				try:
					attId = drsuapi.OidFromAttid(prefixTable, attr['attrTyp'])
					LOOKUP_TABLE = self.ATTRTYP_TO_ATTID
				except Exception as e:
					logger.debug('Failed to execute OidFromAttid with error %s, fallbacking to fixed table' % e)
					logger.debug('Exception', exc_info=True)
					# Fallbacking to fixed table and hope for the best
					attId = attr['attrTyp']
					LOOKUP_TABLE = self.NAME_TO_ATTRTYP
					
				if attId == LOOKUP_TABLE['dBCSPwd']:
					if attr['AttrVal']['valCount'] > 0:
						encrypteddBCSPwd = b''.join(attr['AttrVal']['pAVal'][0]['pVal'])
						encryptedLMHash = drsuapi.DecryptAttributeValue(self.dce.get_session_key(), encrypteddBCSPwd)
						us.lm_hash = drsuapi.removeDESLayer(encryptedLMHash, rid)
					else:
						us.lm_hash = bytes.fromhex('aad3b435b51404eeaad3b435b51404ee')
						
				elif attId == LOOKUP_TABLE['unicodePwd']:
					if attr['AttrVal']['valCount'] > 0:
						encryptedUnicodePwd = b''.join(attr['AttrVal']['pAVal'][0]['pVal'])
						encryptedNTHash = drsuapi.DecryptAttributeValue(self.dce.get_session_key(), encryptedUnicodePwd)
						us.nt_hash = drsuapi.removeDESLayer(encryptedNTHash, rid)
					else:
						us.nt_hash = bytes.fromhex('31d6cfe0d16ae931b73c59d7e0c089c0')
						
				elif attId == LOOKUP_TABLE['userPrincipalName']:
					if attr['AttrVal']['valCount'] > 0:
						try:
							us.domain = b''.join(attr['AttrVal']['pAVal'][0]['pVal']).decode('utf-16le').split('@')[-1]
						except:
							us.domain = None
					else:
						us.domain = None
							
				elif attId == LOOKUP_TABLE['sAMAccountName']:
					if attr['AttrVal']['valCount'] > 0:
						try:
							us.username = b''.join(attr['AttrVal']['pAVal'][0]['pVal']).decode('utf-16le')
						except Exception as e:
							logger.error('Cannot get sAMAccountName for %s' % record['pmsgOut'][replyVersion]['pNC']['StringName'][:-1])
							us.username = 'unknown'
					else:
						logger.error('Cannot get sAMAccountName for %s' % record['pmsgOut'][replyVersion]['pNC']['StringName'][:-1])
						us.username = 'unknown'
							
				elif attId == LOOKUP_TABLE['objectSid']:
					if attr['AttrVal']['valCount'] > 0:
						us.object_sid = SID.from_bytes(b''.join(attr['AttrVal']['pAVal'][0]['pVal']))
					else:
						logger.error('Cannot get objectSid for %s' % record['pmsgOut'][replyVersion]['pNC']['StringName'][:-1])
						us.object_sid = rid
				elif attId == LOOKUP_TABLE['pwdLastSet']:
					if attr['AttrVal']['valCount'] > 0:
						try:
							
							us.pwd_last_set = FILETIME.from_bytes(b''.join(attr['AttrVal']['pAVal'][0]['pVal'])).datetime.isoformat()
						except Exception as e:
							
							logger.error('Cannot get pwdLastSet for %s' % record['pmsgOut'][replyVersion]['pNC']['StringName'][:-1])
							us.pwd_last_set = None
							
				elif attId == LOOKUP_TABLE['userAccountControl']:
					if attr['AttrVal']['valCount'] > 0:
						us.user_account_status = int.from_bytes(b''.join(attr['AttrVal']['pAVal'][0]['pVal']), 'little', signed = False)
					else:
						us.user_account_status = None
						
				if attId == LOOKUP_TABLE['lmPwdHistory']:
					if attr['AttrVal']['valCount'] > 0:
						encryptedLMHistory = b''.join(attr['AttrVal']['pAVal'][0]['pVal'])
						tmpLMHistory = drsuapi.DecryptAttributeValue(self.dce.get_session_key(), encryptedLMHistory)
						for i in range(0, len(tmpLMHistory) // 16):
							LMHashHistory = drsuapi.removeDESLayer(tmpLMHistory[i * 16:(i + 1) * 16], rid)
							us.lm_history.append(LMHashHistory)
					else:
						logger.debug('No lmPwdHistory for user %s' % record['pmsgOut'][replyVersion]['pNC']['StringName'][:-1])
				elif attId == LOOKUP_TABLE['ntPwdHistory']:
					if attr['AttrVal']['valCount'] > 0:
						encryptedNTHistory = b''.join(attr['AttrVal']['pAVal'][0]['pVal'])
						tmpNTHistory = drsuapi.DecryptAttributeValue(self.dce.get_session_key(), encryptedNTHistory)
						for i in range(0, len(tmpNTHistory) // 16):
							NTHashHistory = drsuapi.removeDESLayer(tmpNTHistory[i * 16:(i + 1) * 16], rid)
							us.nt_history.append(NTHashHistory)
					else:
						logger.debug('No ntPwdHistory for user %s' % record['pmsgOut'][replyVersion]['pNC']['StringName'][:-1])
						
				elif attId == LOOKUP_TABLE['supplementalCredentials']:
					if attr['AttrVal']['valCount'] > 0:
						blob = b''.join(attr['AttrVal']['pAVal'][0]['pVal'])
						supplementalCredentials = drsuapi.DecryptAttributeValue(self.dce.get_session_key(), blob)
						if len(supplementalCredentials) < 24:
							supplementalCredentials = None
							
						else:
							try:
								user_properties = samr.USER_PROPERTIES(supplementalCredentials)
							except Exception as e:
								# On some old w2k3 there might be user properties that don't
								# match [MS-SAMR] structure, discarding them
								pass
				
			
			if user_properties is not None:
				propertiesData = user_properties['UserProperties']
				for propertyCount in range(user_properties['PropertyCount']):
					userProperty = samr.USER_PROPERTY(propertiesData)
					propertiesData = propertiesData[len(userProperty):]
					# For now, we will only process Newer Kerberos Keys and CLEARTEXT
					if userProperty['PropertyName'].decode('utf-16le') == 'Primary:Kerberos-Newer-Keys':
						propertyValueBuffer = bytes.fromhex(userProperty['PropertyValue'].decode())
						kerbStoredCredentialNew = samr.KERB_STORED_CREDENTIAL_NEW(propertyValueBuffer)
						data = kerbStoredCredentialNew['Buffer']
						for credential in range(kerbStoredCredentialNew['CredentialCount']):
							keyDataNew = samr.KERB_KEY_DATA_NEW(data)
							data = data[len(keyDataNew):]
							keyValue = propertyValueBuffer[keyDataNew['KeyOffset']:][:keyDataNew['KeyLength']]

							if  keyDataNew['KeyType'] in self.KERBEROS_TYPE:
								answer =  (self.KERBEROS_TYPE[keyDataNew['KeyType']],keyValue)
							else:
								answer =  (hex(keyDataNew['KeyType']),keyValue)
							# We're just storing the keys, not printing them, to make the output more readable
							# This is kind of ugly... but it's what I came up with tonight to get an ordered
							# set :P. Better ideas welcomed ;)
							us.kerberos_keys.append(answer)
					elif userProperty['PropertyName'].decode('utf-16le') == 'Primary:CLEARTEXT':
						# [MS-SAMR] 3.1.1.8.11.5 Primary:CLEARTEXT Property
						# This credential type is the cleartext password. The value format is the UTF-16 encoded cleartext password.
						# SkelSec: well, almost. actually the property is the hex-encoded bytes of an UTF-16LE encoded plaintext string
						encoded_pw = bytes.fromhex(userProperty['PropertyValue'].decode('ascii'))
						try:
							answer = encoded_pw.decode('utf-16le')
						except UnicodeDecodeError:
							# This could be because we're decoding a machine password. Printing it hex
							answer = encoded_pw.decode('utf-8')

						us.cleartext_pwds.append(answer)
				
		
			return us, None
		
		except Exception as e:
			return None, e
			
	@red
	async def DRSCrackNames(self, formatOffered=drsuapi.DS_NAME_FORMAT.DS_DISPLAY_NAME, formatDesired=drsuapi.DS_NAME_FORMAT.DS_FQDN_1779_NAME, name=''):
		if self.handle is None:
			await rr(self.open())

		logger.debug('Calling DRSCrackNames for %s' % name)
		resp, _ = await rr(drsuapi.hDRSCrackNames(self.dce, self.handle, 0, formatOffered, formatDesired, (name,)))
		return resp, None
	
	async def DRSGetNCChanges(self, guid, req_attributes = {}):
		try:
			if self.handle is None:
				await rr(self.open())

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

			data, err = await self.dce.request(request)
			return data, err
		except Exception as e:
			print('err!')
			return None, e


	async def DRSGetNT4ChangeLog(self):
		if self.handle is None:
			await rr(self.open())

		try:
			logger.debug('Calling DRSGetNT4ChangeLog')
			resp, _ = await rr(drsuapi.hDRSGetNT4ChangeLog(self.dce, self.handle))
			return resp, None
		except Exception as e:
			return None, e

	
	@red
	async def close(self):
		if self.handle:
			try:
				await rr(drsuapi.hDRSUnbind(self.dce, self.handle))
			except:
				pass
		if self.dce:
			try:
				await rr(self.dce.disconnect())
			except:
				pass
		
		return True,None