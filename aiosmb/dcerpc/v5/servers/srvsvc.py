"""Read-only SRVSVC interface for the minimal SMB file server."""

import asyncio
import inspect
from dataclasses import dataclass
from typing import Any, Callable, Iterable, List, Mapping, Optional

from aiosmb.dcerpc.v5 import srvs, system_errors
from aiosmb.dcerpc.v5.ndr import NULL
from aiosmb.dcerpc.v5.servers.runtime import DCERPCServerRuntime


NERR_NET_NAME_NOT_FOUND = 2310


@dataclass(frozen=True)
class SRVSVCShare:
	"""Provider-neutral share metadata exposed by SRVSVC."""

	name: str
	path: str = ''
	remark: str = ''
	share_type: int = srvs.STYPE_DISKTREE
	permissions: int = 0
	max_uses: int = 0xFFFFFFFF
	current_uses: int = 0
	password: str = ''


def _terminated(value: Any) -> str:
	return str(value).rstrip('\x00') + '\x00'


class SRVSVCServer:
	"""Serve the read-only calls needed for SMB share discovery.

	``share_provider`` is called for every request.  It may return a mapping of
	share names to paths/metadata, or an iterable of ``SRVSVCShare``/mapping
	records, and it may be asynchronous.  IPC$ is added when the provider does
	not supply it.
	"""

	def __init__(
		self,
		transport=None,
		share_provider: Optional[Callable[[], Any]] = None,
		server_name: str = 'AIOSMB',
		server_comment: str = 'aiosmb SMB server',
		version_major: int = 10,
		version_minor: int = 0,
		runtime: Optional[DCERPCServerRuntime] = None,
	):
		if share_provider is not None and not callable(share_provider):
			raise TypeError('share_provider must be callable')
		self.transport = transport
		self.share_provider = share_provider or (lambda: {})
		self.server_name = server_name.rstrip('\x00')
		self.server_comment = server_comment.rstrip('\x00')
		self.version_major = version_major
		self.version_minor = version_minor
		self.runtime = runtime or DCERPCServerRuntime(
			secondary_address=b'\\pipe\\srvsvc\x00'
		)
		self.runtime.register_interface(
			srvs.MSRPC_UUID_SRVS,
			{
				srvs.NetrShareEnum.opnum: self._netr_share_enum,
				srvs.NetrShareGetInfo.opnum: self._netr_share_get_info,
				srvs.NetrServerGetInfo.opnum: self._netr_server_get_info,
			},
		)
		self._serve_task = None

	async def _provider_shares(self) -> List[SRVSVCShare]:
		value = self.share_provider()
		if inspect.isawaitable(value):
			value = await value

		shares: List[SRVSVCShare] = []
		if isinstance(value, Mapping):
			for name, metadata in value.items():
				shares.append(self._coerce_share(name, metadata))
		elif value is None:
			pass
		elif isinstance(value, (str, bytes, bytearray)):
			raise TypeError('share provider must not return a string')
		else:
			for metadata in value:
				shares.append(self._coerce_share(None, metadata))

		by_name = {}
		for share in shares:
			if not share.name:
				raise ValueError('share names must not be empty')
			by_name[share.name.casefold()] = share
		if 'ipc$' not in by_name:
			by_name['ipc$'] = SRVSVCShare(
				name='IPC$',
				remark='Remote IPC',
				share_type=srvs.STYPE_IPC | srvs.STYPE_SPECIAL,
			)
		return sorted(by_name.values(), key=lambda item: item.name.casefold())

	@staticmethod
	def _coerce_share(name_hint: Optional[str], value: Any) -> SRVSVCShare:
		if isinstance(value, SRVSVCShare):
			if name_hint is None or value.name:
				return value
			return SRVSVCShare(
				name=str(name_hint),
				path=value.path,
				remark=value.remark,
				share_type=value.share_type,
				permissions=value.permissions,
				max_uses=value.max_uses,
				current_uses=value.current_uses,
				password=value.password,
			)

		if isinstance(value, Mapping):
			name = value.get(
				'name', value.get('netname', value.get('shi1_netname', name_hint))
			)
			if name is None:
				raise ValueError('share metadata is missing a name')
			return SRVSVCShare(
				name=str(name).rstrip('\x00'),
				path=str(value.get('path', value.get('shi2_path', ''))),
				remark=str(
					value.get('remark', value.get('comment', ''))
				),
				share_type=int(
					value.get(
						'share_type',
						value.get('type', srvs.STYPE_DISKTREE),
					)
				),
				permissions=int(value.get('permissions', 0)),
				max_uses=int(value.get('max_uses', 0xFFFFFFFF)),
				current_uses=int(value.get('current_uses', 0)),
				password=str(value.get('password', '')),
			)

		if name_hint is not None:
			path = '' if value is None else str(value)
			return SRVSVCShare(
				name=str(name_hint).rstrip('\x00'),
				path=path,
			)

		if isinstance(value, (tuple, list)) and len(value) == 2:
			return SRVSVCShare(name=str(value[0]), path=str(value[1]))

		name = getattr(value, 'name', None)
		if name is None:
			raise TypeError('unsupported share provider record')
		return SRVSVCShare(
			name=str(name).rstrip('\x00'),
			path=str(getattr(value, 'path', '')),
			remark=str(getattr(value, 'remark', '')),
			share_type=int(
				getattr(value, 'share_type', srvs.STYPE_DISKTREE)
			),
			permissions=int(getattr(value, 'permissions', 0)),
			max_uses=int(getattr(value, 'max_uses', 0xFFFFFFFF)),
			current_uses=int(getattr(value, 'current_uses', 0)),
			password=str(getattr(value, 'password', '')),
		)

	async def _netr_share_enum(self, stub: bytes) -> bytes:
		request = srvs.NetrShareEnum(stub)
		level = request['InfoStruct']['Level']
		if level not in (0, 1, 2):
			return self._share_enum_response(
				0, [], system_errors.ERROR_INVALID_LEVEL
			).getData()
		shares = await self._provider_shares()
		return self._share_enum_response(level, shares).getData()

	def _share_enum_response(
		self,
		level: int,
		shares: Iterable[SRVSVCShare],
		error_code: int = system_errors.ERROR_SUCCESS,
	):
		shares = list(shares)
		response = srvs.NetrShareEnumResponse()
		response['InfoStruct']['Level'] = level
		response['InfoStruct']['ShareInfo']['tag'] = level
		container = response['InfoStruct']['ShareInfo']['Level%d' % level]
		container['EntriesRead'] = len(shares)
		container['Buffer'] = [
			self._share_info(level, share) for share in shares
		]
		response['TotalEntries'] = len(shares)
		response['ResumeHandle'] = 0
		response['ErrorCode'] = error_code
		return response

	async def _netr_share_get_info(self, stub: bytes) -> bytes:
		request = srvs.NetrShareGetInfo(stub)
		level = request['Level']
		if level not in (0, 1, 2):
			return self._share_get_info_error(
				system_errors.ERROR_INVALID_LEVEL
			).getData()

		net_name = request['NetName'].rstrip('\x00').casefold()
		shares = await self._provider_shares()
		share = next(
			(item for item in shares if item.name.casefold() == net_name),
			None,
		)
		if share is None:
			response = srvs.NetrShareGetInfoResponse()
			response['InfoStruct']['tag'] = level
			response['InfoStruct']['ShareInfo%d' % level] = NULL
			response['ErrorCode'] = NERR_NET_NAME_NOT_FOUND
			return response.getData()

		response = srvs.NetrShareGetInfoResponse()
		response['InfoStruct']['tag'] = level
		response['InfoStruct']['ShareInfo%d' % level] = self._share_info(
			level, share
		)
		response['ErrorCode'] = system_errors.ERROR_SUCCESS
		return response.getData()

	@staticmethod
	def _share_get_info_error(error_code: int):
		response = srvs.NetrShareGetInfoResponse()
		response['InfoStruct']['tag'] = 0
		response['InfoStruct']['ShareInfo0'] = NULL
		response['ErrorCode'] = error_code
		return response

	@staticmethod
	def _share_info(level: int, share: SRVSVCShare):
		if level == 0:
			info = srvs.SHARE_INFO_0()
			info['shi0_netname'] = _terminated(share.name)
			return info
		if level == 1:
			info = srvs.SHARE_INFO_1()
			info['shi1_netname'] = _terminated(share.name)
			info['shi1_type'] = share.share_type
			info['shi1_remark'] = _terminated(share.remark)
			return info
		if level == 2:
			info = srvs.SHARE_INFO_2()
			info['shi2_netname'] = _terminated(share.name)
			info['shi2_type'] = share.share_type
			info['shi2_remark'] = _terminated(share.remark)
			info['shi2_permissions'] = share.permissions
			info['shi2_max_uses'] = share.max_uses
			info['shi2_current_uses'] = share.current_uses
			info['shi2_path'] = _terminated(share.path)
			info['shi2_passwd'] = _terminated(share.password)
			return info
		raise ValueError('unsupported share information level')

	async def _netr_server_get_info(self, stub: bytes) -> bytes:
		request = srvs.NetrServerGetInfo(stub)
		level = request['Level']
		if level not in (100, 101):
			return self._server_get_info_error(
				system_errors.ERROR_INVALID_LEVEL
			).getData()

		response = srvs.NetrServerGetInfoResponse()
		response['InfoStruct']['tag'] = level
		if level == 100:
			info = srvs.SERVER_INFO_100()
			info['sv100_platform_id'] = srvs.PLATFORM_ID_NT
			info['sv100_name'] = _terminated(self.server_name)
			response['InfoStruct']['ServerInfo100'] = info
		else:
			info = srvs.SERVER_INFO_101()
			info['sv101_platform_id'] = srvs.PLATFORM_ID_NT
			info['sv101_name'] = _terminated(self.server_name)
			info['sv101_version_major'] = self.version_major
			info['sv101_version_minor'] = self.version_minor
			info['sv101_type'] = (
				srvs.SV_TYPE_SERVER | srvs.SV_TYPE_SERVER_NT
			)
			info['sv101_comment'] = _terminated(self.server_comment)
			response['InfoStruct']['ServerInfo101'] = info
		response['ErrorCode'] = system_errors.ERROR_SUCCESS
		return response.getData()

	@staticmethod
	def _server_get_info_error(error_code: int):
		response = srvs.NetrServerGetInfoResponse()
		response['InfoStruct']['tag'] = 100
		response['InfoStruct']['ServerInfo100'] = NULL
		response['ErrorCode'] = error_code
		return response

	async def feed_data(self, data: bytes):
		"""Direct byte-stream API useful to SMB pipe implementations."""

		return await self.runtime.feed_data(data)

	async def serve_forever(self):
		if self.transport is None:
			raise RuntimeError('SRVSVCServer has no transport')
		await self.runtime.serve(self.transport)

	async def run(self):
		"""Start serving and return the created task."""

		if self._serve_task is not None and not self._serve_task.done():
			return self._serve_task
		if self.transport is None:
			raise RuntimeError('SRVSVCServer has no transport')
		if hasattr(self.transport, 'run'):
			await self.transport.run()
		self._serve_task = asyncio.create_task(self.serve_forever())
		return self._serve_task

	async def close(self):
		if self.transport is not None and hasattr(
			self.transport, 'disconnect'
		):
			await self.transport.disconnect()
		if self._serve_task is not None and not self._serve_task.done():
			self._serve_task.cancel()
			try:
				await self._serve_task
			except asyncio.CancelledError:
				pass