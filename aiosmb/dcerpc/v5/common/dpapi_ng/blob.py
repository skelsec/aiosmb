# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import io
import dataclasses
import enum
import typing as t
import uuid

from asn1crypto.cms import ContentInfo

from aiosmb.dcerpc.v5.common.dpapi_ng._security_descriptor import ace_to_bytes, sd_to_bytes

@dataclasses.dataclass(frozen=True)
class KeyIdentifier:
	"""Key Identifier.

	This contains the key identifier info that can be used by MS-GKDI GetKey
	to retrieve the group key seed values. This structure is not defined
	publicly by Microsoft but it closely matches the :class:`GroupKeyEnvelope`
	structure.

	Args:
		version: The version of the structure, should be 1
		flags: Flags describing the values inside the structure
		l0: The L0 index of the key
		l1: The L1 index of the key
		l2: The L2 index of the key
		root_key_identifier: The key identifier
		key_info: If is_public_key this is the public key, else it is the key
			KDF context value.
		domain_name: The domain name of the server in DNS format.
		forest_name: The forest name of the server in DNS format.
	"""

	version: int
	magic: bytes = dataclasses.field(init=False, repr=False, default=b"\x4B\x44\x53\x4B")
	flags: int
	l0: int
	l1: int
	l2: int
	root_key_identifier: uuid.UUID
	key_info: bytes
	domain_name: str
	forest_name: str

	@property
	def is_public_key(self) -> bool:
		return bool(self.flags & 1)

	def pack(self) -> bytes:
		b_domain_name = (self.domain_name + "\00").encode("utf-16-le")
		b_forest_name = (self.forest_name + "\00").encode("utf-16-le")

		return b"".join(
			[
				self.version.to_bytes(4, byteorder="little"),
				self.magic,
				self.flags.to_bytes(4, byteorder="little"),
				self.l0.to_bytes(4, byteorder="little"),
				self.l1.to_bytes(4, byteorder="little"),
				self.l2.to_bytes(4, byteorder="little"),
				self.root_key_identifier.bytes_le,
				len(self.key_info).to_bytes(4, byteorder="little"),
				len(b_domain_name).to_bytes(4, byteorder="little"),
				len(b_forest_name).to_bytes(4, byteorder="little"),
				self.key_info,
				b_domain_name,
				b_forest_name,
			]
		)

	@classmethod
	def unpack(
		cls,
		data: t.Union[bytes, bytearray, memoryview],
	) -> KeyIdentifier:
		view = memoryview(data)

		version = int.from_bytes(view[:4], byteorder="little")

		if view[4:8].tobytes() != cls.magic:
			raise ValueError(f"Failed to unpack {cls.__name__} as magic identifier is invalid")

		flags = int.from_bytes(view[8:12], byteorder="little")
		l0_index = int.from_bytes(view[12:16], byteorder="little")
		l1_index = int.from_bytes(view[16:20], byteorder="little")
		l2_index = int.from_bytes(view[20:24], byteorder="little")
		root_key_identifier = uuid.UUID(bytes_le=view[24:40].tobytes())
		key_info_len = int.from_bytes(view[40:44], byteorder="little")
		domain_len = int.from_bytes(view[44:48], byteorder="little")
		forest_len = int.from_bytes(view[48:52], byteorder="little")
		view = view[52:]

		key_info = view[:key_info_len].tobytes()
		view = view[key_info_len:]

		# Take away 2 for the final null padding
		domain = view[: domain_len - 2].tobytes().decode("utf-16-le")
		view = view[domain_len:]

		forest = view[: forest_len - 2].tobytes().decode("utf-16-le")
		view = view[forest_len:]

		return KeyIdentifier(
			version=version,
			flags=flags,
			l0=l0_index,
			l1=l1_index,
			l2=l2_index,
			root_key_identifier=root_key_identifier,
			key_info=key_info,
			domain_name=domain,
			forest_name=forest,
		)
		
@dataclasses.dataclass(frozen=True)
class KeyIdentifier:
	"""Key Identifier.

	This contains the key identifier info that can be used by MS-GKDI GetKey
	to retrieve the group key seed values. This structure is not defined
	publicly by Microsoft but it closely matches the :class:`GroupKeyEnvelope`
	structure.

	Args:
		version: The version of the structure, should be 1
		flags: Flags describing the values inside the structure
		l0: The L0 index of the key
		l1: The L1 index of the key
		l2: The L2 index of the key
		root_key_identifier: The key identifier
		key_info: If is_public_key this is the public key, else it is the key
			KDF context value.
		domain_name: The domain name of the server in DNS format.
		forest_name: The forest name of the server in DNS format.
	"""

	version: int
	magic: bytes = dataclasses.field(init=False, repr=False, default=b"\x4B\x44\x53\x4B")
	flags: int
	l0: int
	l1: int
	l2: int
	root_key_identifier: uuid.UUID
	key_info: bytes
	domain_name: str
	forest_name: str

	@property
	def is_public_key(self) -> bool:
		return bool(self.flags & 1)

	def pack(self) -> bytes:
		b_domain_name = (self.domain_name + "\00").encode("utf-16-le")
		b_forest_name = (self.forest_name + "\00").encode("utf-16-le")

		return b"".join(
			[
				self.version.to_bytes(4, byteorder="little"),
				self.magic,
				self.flags.to_bytes(4, byteorder="little"),
				self.l0.to_bytes(4, byteorder="little"),
				self.l1.to_bytes(4, byteorder="little"),
				self.l2.to_bytes(4, byteorder="little"),
				self.root_key_identifier.bytes_le,
				len(self.key_info).to_bytes(4, byteorder="little"),
				len(b_domain_name).to_bytes(4, byteorder="little"),
				len(b_forest_name).to_bytes(4, byteorder="little"),
				self.key_info,
				b_domain_name,
				b_forest_name,
			]
		)

	@classmethod
	def unpack(
		cls,
		data: t.Union[bytes, bytearray, memoryview],
	) -> KeyIdentifier:
		view = memoryview(data)

		version = int.from_bytes(view[:4], byteorder="little")

		if view[4:8].tobytes() != cls.magic:
			raise ValueError(f"Failed to unpack {cls.__name__} as magic identifier is invalid")

		flags = int.from_bytes(view[8:12], byteorder="little")
		l0_index = int.from_bytes(view[12:16], byteorder="little")
		l1_index = int.from_bytes(view[16:20], byteorder="little")
		l2_index = int.from_bytes(view[20:24], byteorder="little")
		root_key_identifier = uuid.UUID(bytes_le=view[24:40].tobytes())
		key_info_len = int.from_bytes(view[40:44], byteorder="little")
		domain_len = int.from_bytes(view[44:48], byteorder="little")
		forest_len = int.from_bytes(view[48:52], byteorder="little")
		view = view[52:]

		key_info = view[:key_info_len].tobytes()
		view = view[key_info_len:]

		# Take away 2 for the final null padding
		domain = view[: domain_len - 2].tobytes().decode("utf-16-le")
		view = view[domain_len:]

		forest = view[: forest_len - 2].tobytes().decode("utf-16-le")
		view = view[forest_len:]

		return KeyIdentifier(
			version=version,
			flags=flags,
			l0=l0_index,
			l1=l1_index,
			l2=l2_index,
			root_key_identifier=root_key_identifier,
			key_info=key_info,
			domain_name=domain,
			forest_name=forest,
		)


class ProtectionDescriptorType(enum.Enum):
	SID = "1.3.6.1.4.1.311.74.1.1"
	KEY_FILE = "1.3.6.1.4.1.311.74.1.2"  # KeyFile in UF8String type
	SDDL = "1.3.6.1.4.1.311.74.1.5"
	LOCAL = "1.3.6.1.4.1.311.74.1.8"


@dataclasses.dataclass(frozen=True)
class ProtectionDescriptor:
	type: ProtectionDescriptorType
	value: str

	def get_target_sd(self) -> bytes:
		raise NotImplementedError()  # pragma: nocover

	def pack(self) -> bytes:
		raise NotImplementedError()  # pragma: nocover

	@classmethod
	def parse(
		cls,
		value: str,
	) -> ProtectionDescriptor:
		# Currently only the SID type is supported
		return SIDDescriptor(value)

	@classmethod
	def unpack(
		cls,
		data: t.Union[bytes, bytearray, memoryview],
	) -> ProtectionDescriptor:
		content_type = data['0']
		value_type = data['1']['0']['0']['0']
		value = data['1']['0']['0']['1']

		if content_type == ProtectionDescriptorType.SID.value and value_type == "SID":
			return SIDDescriptor(value)

		else:
			raise ValueError(f"DPAPI-NG protection descriptor type {content_type} '{value_type}' is unsupported")


@dataclasses.dataclass(frozen=True)
class SIDDescriptor(ProtectionDescriptor):
	type: ProtectionDescriptorType = dataclasses.field(init=False, default=ProtectionDescriptorType.SID)

	def get_target_sd(self) -> bytes:
		# Build the target security descriptor from the SID passed in. This SD
		# contains an ACE per target user with a mask of 0x3 and a final ACE of
		# the current user with a mask of 0x2. When viewing this over the wire
		# the current user is set as S-1-1-0 (World) and the owner/group is
		# S-1-5-18 (SYSTEM).
		return sd_to_bytes(
			owner="S-1-5-18",
			group="S-1-5-18",
			dacl=[ace_to_bytes(self.value, 3), ace_to_bytes("S-1-1-0", 2)],
		)


@dataclasses.dataclass
class DPAPINGBlob:
	MICROSOFT_SOFTWARE_OID = "1.3.6.1.4.1.311.74.1"

	"""DPAPI NG Blob.

	The unpacked DPAPI NG blob that contains the information needed to decrypt
	the encrypted content. The key identifier and protection descriptor can be
	used to generate the KEK. The KEK is used to decrypt the encrypted CEK. The
	CEK can be used to decrypt the encrypted contents.

	Args:
		key_identifier: The key identifier for the KEK.
		protection_descriptor: The protection descriptor that protects the key.
		enc_cek: The encrypted CEK.
		enc_cek_algorithm: The encrypted CEK algorithm OID.
		enc_cek_parameters: The encrypted CEK algorithm parameters.
		enc_content: The encrypted content.
		enc_content_algorithm: The encrypted content algorithm OID.
		enc_content_parameters: The encrypted content parameters.
	"""

	key_identifier: KeyIdentifier
	protection_descriptor: ProtectionDescriptor
	enc_cek: bytes
	enc_cek_algorithm: str
	enc_cek_parameters: t.Optional[bytes]
	enc_content: bytes
	enc_content_algorithm: str
	enc_content_parameters: t.Optional[bytes]

	def pack() -> bytes:
		raise NotImplementedError()

	@classmethod
	def unpack(
		cls,
		data: t.Union[bytes, bytearray, memoryview],
	) -> DPAPINGBlob:
		view = io.BytesIO(data)
		
		
		update_timestamp = int.from_bytes(view.read(8), byteorder='little', signed=False)
		blob_length = int.from_bytes(view.read(4), byteorder='little', signed=False)
		flags = int.from_bytes(view.read(4), byteorder='little', signed=False)
		blob = view.read(blob_length)
		content_info = ContentInfo.load(blob)
		content_info_native = content_info.native

		if 'content_type' not in content_info_native:
			raise ValueError("Invalid DPAPI-NG blob, missing content type")
		if content_info_native['content_type'] != 'enveloped_data':
			raise ValueError(f"Invalid DPAPI-NG blob, unsupported content type: {content_info_native['content_type']}")
		
		enveloped_data = content_info_native['content']
		if enveloped_data['version'] != 'v2':
			raise ValueError(f"Invalid DPAPI-NG blob, unsupported version: {enveloped_data['version']}")
		if len(enveloped_data['recipient_infos']) != 1:
			raise ValueError(f"Invalid DPAPI-NG blob, unsupported recipient infos length: {len(enveloped_data['recipient_infos'])}")
		recipient_info = enveloped_data['recipient_infos'][0]
		if recipient_info['version'] != 'v4':
			raise ValueError(f"Invalid DPAPI-NG blob, unsupported recipient info version: {recipient_info['version']}")

		kek_info = recipient_info
		key_identifier = KeyIdentifier.unpack(kek_info['kekid']['key_identifier'])

		if 'other' in kek_info['kekid']:
			if kek_info['kekid']['other']['key_attr_id'] != DPAPINGBlob.MICROSOFT_SOFTWARE_OID:
				raise ValueError("DPAPI-NG KEK Id is not in the expected format")

			protection_descriptor = ProtectionDescriptor.unpack(kek_info['kekid']['other']['key_attr'])

		else:
			protection_descriptor = ProtectionDescriptor.unpack(b'')

		# Some DPAPI blobs don't include the content in the PKCS7 payload but
		# just append after the blob.
		enc_content = enveloped_data['encrypted_content_info']['encrypted_content']
		if enc_content is None:
			view.seek(16+len(content_info.dump()), io.SEEK_SET)
			enc_content = view.read()

		return DPAPINGBlob(
			key_identifier=key_identifier,
			protection_descriptor=protection_descriptor,
			enc_cek=kek_info['encrypted_key'],
			enc_cek_algorithm=kek_info['key_encryption_algorithm']['algorithm'],
			enc_cek_parameters=kek_info['key_encryption_algorithm']['parameters'],
			enc_content=enc_content,
			enc_content_algorithm=enveloped_data['encrypted_content_info']['content_encryption_algorithm']['algorithm'],
			enc_content_parameters=enveloped_data['encrypted_content_info']['content_encryption_algorithm']['parameters'],
		)

