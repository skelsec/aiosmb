import traceback

from asysocks.unicomm.common.scanner.common import ScannerData, ScannerError

from aiosmb.commons.connection.factory import SMBConnectionFactory
from aiosmb.commons.exceptions import SMBUnsupportedDialectSelected
from aiosmb.protocol.common import SMB2_NEGOTIATE_DIALTECTS_3
from aiosmb.wintypes.ntstatus import NTStatus


class SMBEncryptionRes:
	def __init__(
			self,
			dialect,
			encryption_supported,
			session_encryption_required,
			encryption_enforced,
			probe_status,
		):
		self.dialect = dialect
		self.encryption_supported = encryption_supported
		self.session_encryption_required = session_encryption_required
		self.encryption_enforced = encryption_enforced
		self.probe_status = probe_status

	def get_header(self):
		return [
			'DIALECT',
			'ENCRYPTION_SUPPORTED',
			'SESSION_ENCRYPTION_REQUIRED',
			'ENCRYPTION_ENFORCED',
			'PROBE_STATUS',
		]

	def to_line(self, separator='\t'):
		return separator.join([
			str(self.dialect),
			str(self.encryption_supported),
			str(self.session_encryption_required),
			str(self.encryption_enforced),
			str(self.probe_status),
		])

	def to_dict(self):
		return {
			'DIALECT': self.dialect,
			'ENCRYPTION_SUPPORTED': self.encryption_supported,
			'SESSION_ENCRYPTION_REQUIRED': self.session_encryption_required,
			'ENCRYPTION_ENFORCED': self.encryption_enforced,
			'PROBE_STATUS': self.probe_status,
		}


class SMBEncryptionScanner:
	def __init__(self, factory:SMBConnectionFactory):
		self.factory = factory

	@staticmethod
	def _configure_smb3(connection):
		connection.supported_dialects = dict(SMB2_NEGOTIATE_DIALTECTS_3)

	@staticmethod
	def _dialect_name(connection):
		dialect = getattr(connection, 'selected_dialect', None)
		return None if dialect is None else dialect.name

	@staticmethod
	def _is_smb3_unsupported(error):
		if isinstance(error, SMBUnsupportedDialectSelected):
			return True
		if getattr(error, 'ntstatus', None) == NTStatus.NOT_SUPPORTED:
			return True
		message = str(error).lower()
		return 'dialect' in message and (
			'not supp' in message or 'unsupported' in message
		)

	@staticmethod
	def _is_encryption_rejection(error):
		return getattr(error, 'ntstatus', None) in (
			NTStatus.ACCESS_DENIED,
			NTStatus.NETWORK_ACCESS_DENIED,
		)

	async def run(self, targetid, target, out_queue):
		try:
			baseline = self.factory.create_connection_newtarget(target)
			self._configure_smb3(baseline)
			async with baseline:
				_, err = await baseline.login()
				if err is not None:
					if self._is_smb3_unsupported(err):
						await out_queue.put(ScannerData(
							target,
							SMBEncryptionRes(
								None,
								False,
								False,
								None,
								'SMB3_UNSUPPORTED',
							),
						))
						return
					raise err

				_, err = await baseline.echo()
				if err is not None:
					raise err

				dialect = self._dialect_name(baseline)
				encryption_supported = bool(baseline.SupportsEncryption)
				session_encryption_required = bool(
					baseline.session_encryption_required
				)

			probe = self.factory.create_connection_newtarget(
				target,
				advertise_encryption=False,
			)
			self._configure_smb3(probe)
			async with probe:
				_, err = await probe.login()
				if err is not None:
					if self._is_encryption_rejection(err):
						await out_queue.put(ScannerData(
							target,
							SMBEncryptionRes(
								dialect,
								encryption_supported,
								session_encryption_required,
								True,
								'CLEAR_SESSION_REJECTED',
							),
						))
						return
					raise err

				_, err = await probe.echo()
				if err is not None:
					if self._is_encryption_rejection(err):
						await out_queue.put(ScannerData(
							target,
							SMBEncryptionRes(
								dialect,
								encryption_supported,
								session_encryption_required,
								True,
								'CLEAR_ECHO_REJECTED',
							),
						))
						return
					raise err

			await out_queue.put(ScannerData(
				target,
				SMBEncryptionRes(
					dialect,
					encryption_supported,
					session_encryption_required,
					False,
					'CLEAR_SESSION_ACCEPTED',
				),
			))
		except Exception as e:
			tb = traceback.format_exc().replace('\n', ' ').replace('\r', '')
			await out_queue.put(ScannerError(target, '%s | Traceback: %s' % (e, tb)))
