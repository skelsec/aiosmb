# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Author: Alberto Solino (@agsolino)
#
# Description:
#   Transport implementations for the DCE/RPC protocol.
#

import re
import socket
import binascii
import os
import copy

from aiosmb.dcerpc.v5.rpcrt import DCERPCException, DCERPC_v5, DCERPC_v4

class DCERPCStringBinding:
	parser = re.compile(r'(?:([a-fA-F0-9-]{8}(?:-[a-fA-F0-9-]{4}){3}-[a-fA-F0-9-]{12})@)?' # UUID (opt.)
						+'([_a-zA-Z0-9]*):' # Protocol Sequence
						+'([^\[]*)' # Network Address (opt.)
						+'(?:\[([^\]]*)\])?') # Endpoint and options (opt.)

	def __init__(self, stringbinding, connection):
		match = DCERPCStringBinding.parser.match(stringbinding)
		self.__uuid = match.group(1)
		self.__ps = match.group(2)
		self.__na = match.group(3)
		options = match.group(4)
		if options:
			options = options.split(',')
			self.__endpoint = options[0]
			try:
				self.__endpoint.index('endpoint=')
				self.__endpoint = self.__endpoint[len('endpoint='):]
			except:
				pass
			self.__options = options[1:]
		else:
			self.__endpoint = ''
			self.__options = []

	def get_uuid(self):
		return self.__uuid

	def get_protocol_sequence(self):
		return self.__ps

	def get_network_address(self):
		return self.__na

	def get_endpoint(self):
		return self.__endpoint

	def get_options(self):
		return self.__options

	def __str__(self):
		return DCERPCStringBindingCompose(self.__uuid, self.__ps, self.__na, self.__endpoint, self.__options), connection
		
		
def DCERPCStringBindingCompose(uuid=None, protocol_sequence='', network_address='', endpoint='', options=[]):
	s = ''
	if uuid: s += uuid + '@'
	s += protocol_sequence + ':'
	if network_address: s += network_address
	if endpoint or options:
		s += '[' + endpoint
		if options: s += ',' + ','.join(options)
		s += ']'

	return s	

class DCERPCTransport:

	DCERPC_class = DCERPC_v5

	def __init__(self, connection, remoteName, dstport):
		self.__connection = connection
		self.__remoteName = remoteName
		self.__remoteHost = remoteName
		self.__dstport = dstport
		self._max_send_frag = None
		self._max_recv_frag = None
		self._domain = ''
		self._lmhash = ''
		self._nthash = ''
		self.__connect_timeout = None
		self._doKerberos = False
		self._username = ''
		self._password = ''
		self._domain   = ''
		self._aesKey   = None
		self._TGT	  = None
		self._TGS	  = None
		self._kdcHost  = None
		self.set_credentials('','')
		
		#Added by SkelSec:
		self._ntlm_ctx = None
		self._kerberos_ctx = None
		self._spnego_ctx = None
		
	def is_kerberos(self):
		if self._kerberos_ctx is not None:
			return True
		return 'MS KRB5 - Microsoft Kerberos 5' in self.__connection.gssapi.list_original_conexts()
		
	def is_ntlm(self):
		if self._ntlm_ctx is not None:
			return True
		return 'NTLMSSP - Microsoft NTLM Security Support Provider' in self.__connection.gssapi.list_original_conexts()
		
	def get_spnego(self):
		if not self._spnego_ctx:
			self._spnego_ctx = copy.deepcopy(self.__connection.original_gssapi)
		return self._spnego_ctx
		
	def get_ntlm_ctx(self):
		if not self._ntlm_ctx:
			self._ntlm_ctx = self.__connection.gssapi.get_original_context('NTLMSSP - Microsoft NTLM Security Support Provider')
		return self._ntlm_ctx
		
	def get_kerberos_ctx(self):
		if not self._kerberos_ctx:
			self._kerberos_ctx = self.__connection.gssapi.get_original_context('MS KRB5 - Microsoft Kerberos 5')
		return self._kerberos_ctx

	async def connect(self):
		raise RuntimeError('virtual function')
	async def send(self,data=0, forceWriteAndx = 0, forceRecv = 0):
		raise RuntimeError('virtual function')
	async def recv(self, forceRecv = 0, count = 0):
		raise RuntimeError('virtual function')
	async def disconnect(self):
		raise RuntimeError('virtual function')
	def get_socket(self):
		raise RuntimeError('virtual function')

	def get_connect_timeout(self):
		return self.__connect_timeout
	def set_connect_timeout(self, timeout):
		self.__connect_timeout = timeout

	def getRemoteName(self):
		return self.__remoteName

	def setRemoteName(self, remoteName):
		"""This method only makes sense before connection for most protocols."""
		self.__remoteName = remoteName

	def getRemoteHost(self):
		return self.__remoteHost

	def setRemoteHost(self, remoteHost):
		"""This method only makes sense before connection for most protocols."""
		self.__remoteHost = remoteHost

	def get_dport(self):
		return self.__dstport
	def set_dport(self, dport):
		"""This method only makes sense before connection for most protocols."""
		self.__dstport = dport

	def get_addr(self):
		return self.getRemoteHost(), self.get_dport()
	def set_addr(self, addr):
		"""This method only makes sense before connection for most protocols."""
		self.setRemoteHost(addr[0])
		self.set_dport(addr[1])

	def set_kerberos(self, flag, kdcHost = None):
		self._doKerberos = flag
		self._kdcHost = kdcHost

	def get_kerberos(self):
		return self._doKerberos

	def get_kdcHost(self):
		return self._kdcHost

	def set_max_fragment_size(self, send_fragment_size):
		# -1 is default fragment size: 0 (don't fragment)
		#  0 is don't fragment
		#	other values are max fragment size
		if send_fragment_size == -1:
			self.set_default_max_fragment_size()
		else:
			self._max_send_frag = send_fragment_size

	def set_default_max_fragment_size(self):
		# default is 0: don't fragment.
		# subclasses may override this method
		self._max_send_frag = 0

	def get_credentials(self):
		return (
			self._username,
			self._password,
			self._domain,
			self._lmhash,
			self._nthash,
			self._aesKey,
			self._TGT, 
			self._TGS)

	def set_credentials(self, username, password, domain='', lmhash='', nthash='', aesKey='', TGT=None, TGS=None):
		self._username = username
		self._password = password
		self._domain   = domain
		self._aesKey   = aesKey
		self._TGT	  = TGT
		self._TGS	  = TGS
		if lmhash != '' or nthash != '':
			if len(lmhash) % 2:	 lmhash = '0%s' % lmhash
			if len(nthash) % 2:	 nthash = '0%s' % nthash
			try: # just in case they were converted already
			   self._lmhash = binascii.unhexlify(lmhash)
			   self._nthash = binascii.unhexlify(nthash)
			except:
			   self._lmhash = lmhash
			   self._nthash = nthash
			   pass

	def doesSupportNTLMv2(self):
		# By default we'll be returning the library's default. Only on SMB Transports we might be able to know it beforehand
		return ntlm.USE_NTLMv2

	def get_dce_rpc(self):
		return DCERPC_v5(self)
