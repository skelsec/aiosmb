
from typing import List

from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR

from aiosmb.connection import SMBConnection
from aiosmb.dcerpc.v5.dcom.connection import DCOMConnection
from aiosmb.dcerpc.v5.dcom import certadmin
from aiosmb.dcerpc.v5.dcom.certadmin import ICertAdminD2, EditFlags, InterfaceFlags, CAAccessMask
from aiosmb.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY

### MS-CSRA is a DCOM interface, this does not work over SMB, only TCP/IP!
### Only the read-only part of the protocol is implemented.


class ICertAdminRPC:
	def __init__(self):
		self.dcom:DCOMConnection = None
		self.iface:ICertAdminD2 = None
		self.ca_name:str = None

	async def __aenter__(self):
		return self

	async def __aexit__(self, exc_type, exc, traceback):
		await self.close()

	async def close(self):
		try:
			if self.iface is not None:
				try:
					await self.iface.RemRelease()
				except:
					pass
				self.iface = None
			if self.dcom is not None:
				try:
					await self.dcom.disconnect()
				except:
					pass
				self.dcom = None
			return True, None
		except Exception as e:
			return None, e

	@staticmethod
	async def from_dcomconnection(dcom:DCOMConnection, ca_name:str = None):
		"""
		Activates the CA admin object on an already connected DCOMConnection.
		If ca_name is not given, the name of the CA active on the server is used.
		"""
		try:
			service = ICertAdminRPC()
			service.dcom = dcom
			iInterface, err = await dcom.CoCreateInstanceEx(certadmin.CLSID_CCertAdminD, certadmin.IID_ICertAdminD2)
			if err is not None:
				raise err
			service.iface = ICertAdminD2(iInterface)

			service.ca_name = ca_name
			if ca_name is None:
				service.ca_name, err = await service.get_active_ca_name()
				if err is not None:
					raise err

			return service, None
		except Exception as e:
			return None, e

	@staticmethod
	async def from_smbconnection(connection:SMBConnection, ca_name:str = None, auth_level = None):
		"""
		Creates the connection to the service using the target and credentials
		of an established SMBConnection.
		The CA only accepts admin calls with packet privacy by default.
		"""
		dcom = None
		try:
			if auth_level is None:
				auth_level = RPC_C_AUTHN_LEVEL_PKT_PRIVACY

			dcom = DCOMConnection.from_smbconnection(connection, auth_level=auth_level)
			_, err = await dcom.connect()
			if err is not None:
				raise err

			service, err = await ICertAdminRPC.from_dcomconnection(dcom, ca_name=ca_name)
			if err is not None:
				raise err

			return service, None
		except Exception as e:
			if dcom is not None:
				await dcom.disconnect()
			return None, e

	async def ping(self):
		"""Checks that the CA service is up and responding."""
		return await self.iface.ping(self.ca_name)

	async def get_active_ca_name(self):
		"""Name of the CA active on the server."""
		return await self.iface.get_config_entry('', 'Active')

	async def get_my_roles(self):
		"""CA roles (CAAccessMask) of the user of this connection."""
		return await self.iface.get_my_roles(self.ca_name)

	async def get_config_entry(self, entry:str, node_path:str = ''):
		"""
		Reads a value from the CA's configuration.
		Returns int, str, list of str or bytes depending on the type of the value.
		"""
		return await self.iface.get_config_entry(self.ca_name, entry, node_path)

	async def get_ca_property(self, prop_id:int, prop_type:int, prop_index:int = 0):
		"""Reads a CA property (certadmin.CR_PROP_*) of the given type (certadmin.PROPTYPE_*)."""
		return await self.iface.get_ca_property(self.ca_name, prop_id, prop_type, prop_index)

	async def get_edit_flags(self):
		"""
		EditFlags of the CA's policy module.
		EDITF_ATTRIBUTESUBJECTALTNAME2 set means requesters can specify the SAN (ESC6).
		"""
		try:
			flags, err = await self.get_config_entry('EditFlags', certadmin.POLICY_MODULE_NODE)
			if err is not None:
				raise err
			return EditFlags(flags & 0xFFFFFFFF), None
		except Exception as e:
			return None, e

	async def get_interface_flags(self):
		"""
		InterfaceFlags of the CA.
		IF_ENFORCEENCRYPTICERTREQUEST not set means requests are accepted without packet privacy (ESC11).
		"""
		try:
			flags, err = await self.get_config_entry('InterfaceFlags')
			if err is not None:
				raise err
			return InterfaceFlags(flags & 0xFFFFFFFF), None
		except Exception as e:
			return None, e

	async def get_disable_extension_list(self):
		"""
		OIDs of the extensions the policy module doesn't add to issued certificates.
		Having 1.3.6.1.4.1.311.25.2 (SID security extension) here means ESC16.
		"""
		try:
			oids, err = await self.get_config_entry('DisableExtensionList', certadmin.POLICY_MODULE_NODE)
			if err is not None:
				raise err
			if oids is None:
				return [], None
			if isinstance(oids, str):
				oids = [oids]
			return [oid for oid in oids if oid != ''], None
		except Exception as e:
			return None, e

	async def set_edit_flags(self, flags):
		"""
		Overwrites the EditFlags of the CA's policy module. Requires the
		Manage CA (CA admin) role. Takes effect after a CA service restart.

		Setting EDITF_ATTRIBUTESUBJECTALTNAME2 here is the ESC6 primitive: it
		lets requesters specify an arbitrary SAN on any template (ESC1).

		Args:
			flags: the new EditFlags value (int or EditFlags)

		Returns:
			(True, None) on success
			(None, Exception) on failure
		"""
		return await self.iface.set_config_entry_i4(
			self.ca_name, 'EditFlags', int(flags), certadmin.POLICY_MODULE_NODE
		)

	async def issue_pending_request(self, request_id:int):
		"""
		Issues a pending certificate request. Requires the Manage Certificates
		(CA officer) role.

		Args:
			request_id: id of the pending request to issue

		Returns:
			(disposition, None) on success, disposition is a certadmin.CR_DISP_*
				value (CR_DISP_ISSUED == 3 means the certificate was issued)
			(None, Exception) on failure
		"""
		return await self.iface.resubmit_request(self.ca_name, request_id)

	async def get_ca_security(self):
		"""
		Security descriptor of the CA. The access mask of the ACEs is a CAAccessMask.
		"""
		try:
			sd, err = await self.iface.get_ca_security(self.ca_name)
			if err is not None:
				raise err
			return SECURITY_DESCRIPTOR.from_bytes(sd), None
		except Exception as e:
			return None, e
