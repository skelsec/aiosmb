# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations
from __future__ import division
from __future__ import print_function

import uuid
import os
import enum
import dataclasses
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
import typing as t
import math
from cryptography.hazmat.primitives import hashes, keywrap
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.kdf.kbkdf import KBKDFHMAC, CounterLocation, Mode
from aiosmb.dcerpc.v5.common.dpapi_ng.blob import *


KDS_SERVICE_LABEL = "KDS service\0".encode("utf-16-le")


@dataclasses.dataclass(frozen=True)
class KDFParameters:
	"""KDF Parameters

	The format and field descriptions for the key derivation function (KDF)
	parameters. The format of this struct is defined in
	`MS-GKDI 2.2.1 KDF Parameters`_.

	Args:
		hash_name: The name of the hash algorithm.

	.. _MS-GKDI 2.2.1 KDF Parameters:
		https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/9946aeff-a914-45e9-b9e5-6cb5b4059187
	"""

	hash_name: str

	@property
	def hash_algorithm(self) -> hashes.HashAlgorithm:
		"""The hash algorithm object."""
		if self.hash_name == "SHA1":
			return hashes.SHA1()
		elif self.hash_name == "SHA256":
			return hashes.SHA256()
		elif self.hash_name == "SHA384":
			return hashes.SHA384()
		elif self.hash_name == "SHA512":
			return hashes.SHA512()
		else:
			raise NotImplementedError(f"Unsupported hash algorithm {self.hash_name}")

	def pack(self) -> bytes:
		b_hash_name = (self.hash_name + "\00").encode("utf-16-le")
		return b"".join(
			[
				b"\x00\x00\x00\x00\x01\x00\x00\x00",
				len(b_hash_name).to_bytes(4, byteorder="little"),
				b"\x00\x00\x00\x00",
				b_hash_name,
			]
		)

	@classmethod
	def unpack(
		cls,
		data: t.Union[bytes, bytearray, memoryview],
	) -> KDFParameters:
		view = memoryview(data)

		if view[:8].tobytes() != b"\x00\x00\x00\x00\x01\x00\x00\x00" or view[12:16].tobytes() != b"\x00\x00\x00\x00":
			raise ValueError(f"Failed to unpack {cls.__name__} as magic identifier is invalid")

		hash_length = int.from_bytes(view[8:12], byteorder="little")
		hash_name = view[16 : 16 + hash_length - 2].tobytes().decode("utf-16-le")

		return KDFParameters(hash_name=hash_name)


@dataclasses.dataclass(frozen=True)
class FFCDHParameters:
	"""FFC DH Parameters

	The field parameters for use in deriving finite field cryptography (FFC)
	Diffie-Hellman (DH) keys. The format of this struct is defined in
	`MS-GKDI 2.2.2 FFC DH Parameters`_.

	Args:
		key_length: The length of the public key.
		field_order: The large prime field order, otherwise known as p.
		generator: The generator of the subgroup, otherwise known as g.

	.. _MS-GKDI 2.2.2 FFC DH Parameters:
		https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/e15ae269-ee21-446a-a480-de3ea243db5f
	"""

	key_length: int
	magic: bytes = dataclasses.field(init=False, repr=False, default=b"\x44\x48\x50\x4D")
	field_order: int
	generator: int

	def pack(self) -> bytes:
		b_field_order = self.field_order.to_bytes(self.key_length, byteorder="big")
		b_generator = self.generator.to_bytes(self.key_length, byteorder="big")

		return b"".join(
			[
				(12 + len(b_field_order) + len(b_generator)).to_bytes(4, byteorder="little"),
				self.magic,
				self.key_length.to_bytes(4, byteorder="little"),
				b_field_order,
				b_generator,
			]
		)

	@classmethod
	def unpack(
		cls,
		data: t.Union[bytes, bytearray, memoryview],
	) -> FFCDHParameters:
		view = memoryview(data)

		# length = int.from_bytes(view[:4], byteorder="little")
		if view[4:8].tobytes() != cls.magic:
			raise ValueError(f"Failed to unpack {cls.__name__} as magic identifier is invalid")

		key_length = int.from_bytes(view[8:12], byteorder="little")
		field_order = view[12 : 12 + key_length].tobytes()
		generator = view[12 + key_length : 12 + key_length + key_length].tobytes()

		return FFCDHParameters(
			key_length=key_length,
			field_order=int.from_bytes(field_order, byteorder="big"),
			generator=int.from_bytes(generator, byteorder="big"),
		)


@dataclasses.dataclass(frozen=True)
class FFCDHKey:
	"""FFC DH Key

	The finite field cryptography (FFC) Diffie-Hellman (DH) public key info.
	The format of this struct is defined in `MS-GKDI 2.2.3.1 FFC DH Key`_.

	Args:
		key_length: The length of the public key.
		field_order: The large prime field order, otherwise known as p.
		generator: The generator of the subgroup, otherwise known as g.
		public_key: The public key of the peer, otherwise known as y.

	.. _MS-GKDI 2.2.3.1 FFC DH Key:
		https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/f8770f01-036d-4bf6-a4cf-1bd0e3913404
	"""

	magic: bytes = dataclasses.field(init=False, repr=False, default=b"\x44\x48\x50\x42")
	key_length: int
	field_order: int
	generator: int
	public_key: int

	def pack(self) -> bytes:
		b_field_order = self.field_order.to_bytes(self.key_length, byteorder="big")
		b_generator = self.generator.to_bytes(self.key_length, byteorder="big")
		b_pub_key = self.public_key.to_bytes(self.key_length, byteorder="big")

		return b"".join(
			[
				self.magic,
				self.key_length.to_bytes(4, byteorder="little"),
				b_field_order,
				b_generator,
				b_pub_key,
			]
		)

	@classmethod
	def unpack(
		cls,
		data: t.Union[bytes, bytearray, memoryview],
	) -> FFCDHKey:
		view = memoryview(data)

		if view[:4].tobytes() != cls.magic:
			raise ValueError(f"Failed to unpack {cls.__name__} as magic identifier is invalid")

		key_length = int.from_bytes(view[4:8], byteorder="little")

		field_order = view[8 : 8 + key_length].tobytes()
		view = view[8 + key_length :]

		generator = view[:key_length].tobytes()
		view = view[key_length:]

		public_key = view[:key_length].tobytes()

		return FFCDHKey(
			key_length=key_length,
			field_order=int.from_bytes(field_order, byteorder="big"),
			generator=int.from_bytes(generator, byteorder="big"),
			public_key=int.from_bytes(public_key, byteorder="big"),
		)


@dataclasses.dataclass(frozen=True)
class ECDHKey:
	"""ECDH Key

	The elliptic curve Diffie-Hellman (ECDH) public key info. The format of
	this struct is defined in `MS-GKDI 2.2.3.2 ECDH Key`_.

	Args:
		curve_name: The curve name used, currently only the curves P256, P384,
			P521 are supported.
		key_length: The length of the public key.
		x: The X coordinate of the point P.
		y: The Y coordinate of the point P.

	.. _MS-GKDI 2.2.3.2 ECDH Key:
		https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/24876a37-9a92-4187-9052-222bb6f85d4a
	"""

	magic: bytes = dataclasses.field(init=False, repr=False, default=b"\x45\x43\x4B")
	curve_name: str
	key_length: int
	x: int
	y: int

	@property
	def curve_and_hash(self) -> tuple[ec.EllipticCurve, hashes.HashAlgorithm]:
		return {
			"P256": (ec.SECP256R1(), hashes.SHA256()),
			"P384": (ec.SECP384R1(), hashes.SHA384()),
			"P521": (ec.SECP521R1(), hashes.SHA512()),
		}[self.curve_name]

	def pack(self) -> bytes:
		b_x = self.x.to_bytes(self.key_length, byteorder="big")
		b_y = self.y.to_bytes(self.key_length, byteorder="big")

		b_curve = {
			"P256": b"\x45\x43\x4B\x31",
			"P384": b"\x45\x43\x4B\x33",
			"P521": b"\x45\x43\x4B\x35",
		}.get(self.curve_name, None)
		if not b_curve:
			raise ValueError(f"Unknown curve '{self.curve_name}', cannot pack.")

		return b"".join(
			[
				b_curve,
				self.key_length.to_bytes(4, byteorder="little"),
				b_x,
				b_y,
			]
		)

	@classmethod
	def unpack(
		cls,
		data: t.Union[bytes, bytearray, memoryview],
	) -> ECDHKey:
		view = memoryview(data)

		curve_id = int.from_bytes(view[:4], byteorder="little")
		curve = {
			0x314B4345: "P256",
			0x334B4345: "P384",
			0x354B4345: "P521",
		}.get(curve_id, None)
		if not curve:
			raise ValueError(f"Failed to unpack {cls.__name__} with unknown curve 0x{curve_id:08X}")

		length = int.from_bytes(view[4:8], byteorder="little")

		x = view[8 : 8 + length].tobytes()
		view = view[8 + length :]

		y = view[:length].tobytes()

		return ECDHKey(
			curve_name=curve,
			key_length=length,
			x=int.from_bytes(x, byteorder="big"),
			y=int.from_bytes(y, byteorder="big"),
		)


@dataclasses.dataclass(frozen=True)
class GroupKeyEnvelope:
	"""Group Key Envelope

	The group key envelope structure that describes the group key information
	returned by a GetKey RPC request. The format of this struct is defined in
	`MS-GKDI 2.2.4 Group Key Envelope`_.

	Args:
		version: The version of the structure, should be 1
		flags: Flags describing the values inside the structure
		l0: The L0 index of the key
		l1: The L1 index of the key
		l2: The L2 index of the key
		root_key_identifier: The key identifier
		kdf_algorithm: The KDF algorithm name.
		kdf_parameters: The KDF algorithm parameters
		secret_algorithm: The secret agreement algorithm name.
		secret_parameters: The secret agreement algorithm parameters.
		private_key_length: The private key length associated with the root key.
		public_key_length: The public key length associated with the root key.
		domain_name: The domain name of the server in DNS format.
		forest_name: The forest name of the server in DNS format.
		l1_key: The L1 seed key.
		l2_key: If is_public_key this is the public key, else this is the L2
			seed key.

	.. _MS-GKDI 2.2.4 Group Key Envelope
		https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/192c061c-e740-4aa0-ab1d-6954fb3e58f7
	"""

	version: int
	magic: bytes = dataclasses.field(init=False, repr=False, default=b"\x4B\x44\x53\x4B")
	flags: int
	l0: int
	l1: int
	l2: int
	root_key_identifier: uuid.UUID
	kdf_algorithm: str
	kdf_parameters: bytes
	secret_algorithm: str
	secret_parameters: bytes
	private_key_length: int
	public_key_length: int
	domain_name: str
	forest_name: str
	l1_key: bytes
	l2_key: bytes

	@property
	def is_public_key(self) -> bool:
		"""If True, the value of l2_key is the public key."""
		return bool(self.flags & 1)

	def pack(self) -> bytes:
		b_kdf_algorithm = (self.kdf_algorithm + "\00").encode("utf-16-le")
		b_secret_algorithm = (self.secret_algorithm + "\00").encode("utf-16-le")
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
				len(b_kdf_algorithm).to_bytes(4, byteorder="little"),
				len(self.kdf_parameters).to_bytes(4, byteorder="little"),
				len(b_secret_algorithm).to_bytes(4, byteorder="little"),
				len(self.secret_parameters).to_bytes(4, byteorder="little"),
				self.private_key_length.to_bytes(4, byteorder="little"),
				self.public_key_length.to_bytes(4, byteorder="little"),
				len(self.l1_key).to_bytes(4, byteorder="little"),
				len(self.l2_key).to_bytes(4, byteorder="little"),
				len(b_domain_name).to_bytes(4, byteorder="little"),
				len(b_forest_name).to_bytes(4, byteorder="little"),
				b_kdf_algorithm,
				self.kdf_parameters,
				b_secret_algorithm,
				self.secret_parameters,
				b_domain_name,
				b_forest_name,
				self.l1_key,
				self.l2_key,
			]
		)

	def get_kek(
		self,
		key_id: KeyIdentifier,
	) -> bytes:
		if self.is_public_key:
			raise ValueError("Current user is not authorized to retrieve the KEK information")
		if self.l0 != key_id.l0:
			raise ValueError(f"L0 index {self.l0} does not match the requested L0 index {key_id.l0}")

		if self.kdf_algorithm != "SP800_108_CTR_HMAC":
			raise NotImplementedError(f"Unknown KDF algorithm '{self.kdf_algorithm}'")

		kdf_parameters = KDFParameters.unpack(self.kdf_parameters)
		hash_algo = kdf_parameters.hash_algorithm
		l2_key = compute_l2_key(hash_algo, key_id.l1, key_id.l2, self)

		if key_id.is_public_key:
			return compute_kek_from_public_key(
				algorithm=hash_algo,
				seed=l2_key,
				secret_algorithm=self.secret_algorithm,
				secret_parameters=self.secret_parameters,
				public_key=key_id.key_info,
				private_key_length=math.ceil(self.private_key_length / 8),
			)

		else:
			return kdf(
				hash_algo,
				l2_key,
				KDS_SERVICE_LABEL,
				key_id.key_info,
				32,
			)

	def new_kek(
		self,
	) -> tuple[bytes, KeyIdentifier]:
		if self.kdf_algorithm != "SP800_108_CTR_HMAC":
			raise NotImplementedError(f"Unknown KDF algorithm '{self.kdf_algorithm}'")

		kdf_parameters = KDFParameters.unpack(self.kdf_parameters)
		hash_algo = kdf_parameters.hash_algorithm

		if self.is_public_key:
			# If is_public_key flag is set, the L2 key is the peer's public key
			private_key = os.urandom(math.ceil(self.private_key_length / 8))
			kek = compute_kek(
				algorithm=hash_algo,
				secret_algorithm=self.secret_algorithm,
				secret_parameters=self.secret_parameters,
				private_key=private_key,
				public_key=self.l2_key,
			)

			key_info = compute_public_key(
				secret_algorithm=self.secret_algorithm,
				secret_parameters=self.secret_parameters,
				private_key=private_key,
				peer_public_key=self.l2_key,
			)
		else:
			key_info = os.urandom(32)
			kek = kdf(
				hash_algo,
				self.l2_key,
				KDS_SERVICE_LABEL,
				key_info,
				32,
			)

		key_identifier = KeyIdentifier(
			version=1,
			flags=self.flags,
			l0=self.l0,
			l1=self.l1,
			l2=self.l2,
			root_key_identifier=self.root_key_identifier,
			key_info=key_info,
			domain_name=self.domain_name,
			forest_name=self.forest_name,
		)
		return kek, key_identifier

	@classmethod
	def unpack(
		cls,
		data: t.Union[bytes, bytearray, memoryview],
	) -> GroupKeyEnvelope:
		view = memoryview(data)

		version = int.from_bytes(view[:4], byteorder="little")

		if view[4:8].tobytes() != cls.magic:
			raise ValueError(f"Failed to unpack {cls.__name__} as magic identifier is invalid")

		flags = int.from_bytes(view[8:12], byteorder="little")
		l0_index = int.from_bytes(view[12:16], byteorder="little")
		l1_index = int.from_bytes(view[16:20], byteorder="little")
		l2_index = int.from_bytes(view[20:24], byteorder="little")
		root_key_identifier = uuid.UUID(bytes_le=view[24:40].tobytes())
		kdf_algo_len = int.from_bytes(view[40:44], byteorder="little")
		kdf_para_len = int.from_bytes(view[44:48], byteorder="little")
		sec_algo_len = int.from_bytes(view[48:52], byteorder="little")
		sec_para_len = int.from_bytes(view[52:56], byteorder="little")
		priv_key_len = int.from_bytes(view[56:60], byteorder="little")
		publ_key_len = int.from_bytes(view[60:64], byteorder="little")
		l1_key_len = int.from_bytes(view[64:68], byteorder="little")
		l2_key_len = int.from_bytes(view[68:72], byteorder="little")
		domain_len = int.from_bytes(view[72:76], byteorder="little")
		forest_len = int.from_bytes(view[76:80], byteorder="little")
		view = view[80:]

		kdf_algo = view[: kdf_algo_len - 2].tobytes().decode("utf-16-le")
		view = view[kdf_algo_len:]

		kdf_param = view[:kdf_para_len].tobytes()
		view = view[kdf_para_len:]

		secret_algo = view[: sec_algo_len - 2].tobytes().decode("utf-16-le")
		view = view[sec_algo_len:]

		secret_param = view[:sec_para_len].tobytes()
		view = view[sec_para_len:]

		domain = view[: domain_len - 2].tobytes().decode("utf-16-le")
		view = view[domain_len:]

		forest = view[: forest_len - 2].tobytes().decode("utf-16-le")
		view = view[forest_len:]

		l1_key = view[:l1_key_len].tobytes()
		view = view[l1_key_len:]

		l2_key = view[:l2_key_len].tobytes()
		view = view[l2_key_len:]

		return GroupKeyEnvelope(
			version=version,
			flags=flags,
			l0=l0_index,
			l1=l1_index,
			l2=l2_index,
			root_key_identifier=root_key_identifier,
			kdf_algorithm=kdf_algo,
			kdf_parameters=kdf_param,
			secret_algorithm=secret_algo,
			secret_parameters=secret_param,
			private_key_length=priv_key_len,
			public_key_length=publ_key_len,
			domain_name=domain,
			forest_name=forest,
			l1_key=l1_key,
			l2_key=l2_key,
		)

################################################################################
# Key derivation functions
################################################################################
def kdf(
	algorithm: hashes.HashAlgorithm,
	secret: bytes,
	label: bytes,
	context: bytes,
	length: int,
) -> bytes:
	# KDF(HashAlg, KI, Label, Context, L)
	# where KDF is SP800-108 in counter mode.
	kdf = KBKDFHMAC(
		algorithm=algorithm,
		mode=Mode.CounterMode,
		length=length,
		label=label,
		context=context,
		# MS-SMB2 uses the same KDF function and my implementation that
		# sets a value of 4 seems to work so assume that's the case here.
		rlen=4,
		llen=4,
		location=CounterLocation.BeforeFixed,
		fixed=None,
	)
	return kdf.derive(secret)


def kdf_concat(
	algorithm: hashes.HashAlgorithm,
	shared_secret: bytes,
	algorithm_id: bytes,
	party_uinfo: bytes,
	party_vinfo: bytes,
	length: int,
) -> bytes:
	otherinfo = b"".join([algorithm_id, party_uinfo, party_vinfo])
	return ConcatKDFHash(
		algorithm,
		length=length,
		otherinfo=otherinfo,
	).derive(shared_secret)

def compute_l1_key(
	target_sd: bytes,
	root_key_id: uuid.UUID,
	l0: int,
	root_key: bytes,
	algorithm: hashes.HashAlgorithm,
) -> bytes:
	# Note: 512 is number of bits, we use byte length here
	# Key(SD, RK, L0, -1, -1) = KDF(
	#   HashAlg,
	#   RK.msKds-RootKeyData,
	#   "KDS service",
	#   RKID || L0 || 0xffffffff || 0xffffffff,
	#   512
	# )
	l0_seed = kdf(
		algorithm,
		root_key,
		KDS_SERVICE_LABEL,
		compute_kdf_context(root_key_id, l0, -1, -1),
		64,
	)

	# Key(SD, RK, L0, 31, -1) = KDF(
	#   HashAlg,
	#   Key(SD, RK, L0, -1, -1),
	#   "KDS service",
	#   RKID || L0 || 31 || 0xffffffff || SD,
	#   512
	# )
	return kdf(
		algorithm,
		l0_seed,
		KDS_SERVICE_LABEL,
		compute_kdf_context(root_key_id, l0, 31, -1) + target_sd,
		64,
	)


def compute_l2_key(
	algorithm: hashes.HashAlgorithm,
	request_l1: int,
	request_l2: int,
	rk: GroupKeyEnvelope,
) -> bytes:
	l1 = rk.l1
	l1_key = rk.l1_key
	l2 = rk.l2
	l2_key = rk.l2_key
	reseed_l2 = l2 == 31 or rk.l1 != request_l1

	# MS-GKDI 2.2.4 Group key Envelope
	# If the value in the L2 index field is equal to 31, this contains the
	# L1 key with group key identifier (L0 index, L1 index, -1). In all
	# other cases, this field contains the L1 key with group key identifier
	# (L0 index, L1 index - 1, -1). If this field is present, its length
	# MUST be equal to 64 bytes.
	if l2 != 31 and l1 != request_l1:
		l1 -= 1
	
	while l1 != request_l1:
		reseed_l2 = True
		l1 -= 1

		l1_key = kdf(
			algorithm,
			l1_key,
			KDS_SERVICE_LABEL,
			compute_kdf_context(
				rk.root_key_identifier,
				rk.l0,
				l1,
				-1,
			),
			64,
		)
	
	if reseed_l2:
		l2 = 31
		l2_key = kdf(
			algorithm,
			l1_key,
			KDS_SERVICE_LABEL,
			compute_kdf_context(
				rk.root_key_identifier,
				rk.l0,
				l1,
				l2,
			),
			64,
		)

	
	while l2 != request_l2:
		l2 -= 1

		l2_key = kdf(
			algorithm,
			l2_key,
			KDS_SERVICE_LABEL,
			compute_kdf_context(
				rk.root_key_identifier,
				rk.l0,
				l1,
				l2,
			),
			64,
		)

	return l2_key


def compute_kdf_context(
	key_guid: uuid.UUID,
	l0: int,
	l1: int,
	l2: int,
) -> bytes:
	return b"".join(
		[
			key_guid.bytes_le,
			l0.to_bytes(4, byteorder="little", signed=True),
			l1.to_bytes(4, byteorder="little", signed=True),
			l2.to_bytes(4, byteorder="little", signed=True),
		]
	)


def compute_kek_from_public_key(
	algorithm: hashes.HashAlgorithm,
	seed: bytes,
	secret_algorithm: str,
	secret_parameters: t.Optional[bytes],
	public_key: bytes,
	private_key_length: int,
) -> bytes:
	private_key = kdf(
		algorithm,
		seed,
		KDS_SERVICE_LABEL,
		(secret_algorithm + "\0").encode("utf-16-le"),
		private_key_length,
	)

	return compute_kek(
		algorithm,
		secret_algorithm=secret_algorithm,
		secret_parameters=secret_parameters,
		private_key=private_key,
		public_key=public_key,
	)


def compute_kek(
	algorithm: hashes.HashAlgorithm,
	secret_algorithm: str,
	secret_parameters: t.Optional[bytes],
	private_key: bytes,
	public_key: bytes,
) -> bytes:
	# Special thanks for Grzegorz Tworek (@0gtweet) and Michał Grzegorzewski
	# for providing access to CQDPAPINGPFXDecrypter.exe which contains the
	# BCrypt* APIs Microsoft use to derive the KEK.

	secret_hash_algorithm: hashes.HashAlgorithm
	if secret_algorithm == "DH":
		# p = FFCDHParameters.unpack(secret_parameters or b"")
		# We can derive the shared secret based on the DH formula.
		# s = y**x mod p
		dh_pub_key = FFCDHKey.unpack(public_key)
		shared_secret_int = pow(
			dh_pub_key.public_key,
			int.from_bytes(private_key, byteorder="big"),
			dh_pub_key.field_order,
		)
		shared_secret = shared_secret_int.to_bytes(dh_pub_key.key_length, byteorder="big")
		secret_hash_algorithm = hashes.SHA256()

	elif secret_algorithm.startswith("ECDH_P"):
		ecdh_pub_key_info = ECDHKey.unpack(public_key)
		curve, secret_hash_algorithm = ecdh_pub_key_info.curve_and_hash

		ecdh_pub_key = ec.EllipticCurvePublicNumbers(ecdh_pub_key_info.x, ecdh_pub_key_info.y, curve).public_key()
		ecdh_private = ec.derive_private_key(
			int.from_bytes(private_key, byteorder="big"),
			curve,
		)
		shared_secret = ecdh_private.exchange(ec.ECDH(), ecdh_pub_key)

	else:
		raise NotImplementedError(f"Unknown secret agreement algorithm '{secret_algorithm}'")

	# This part isn't documented but we use the key derivation algorithm
	# SP 800-56A to derive the kek secret input value. On Windows this uses
	# BCryptDeriveKey with the following parameters.
	#   KDF_ALGORITHMID - SHA512
	#   KDF_PARTYUINFO  - KDS public key
	#   KDF_PARTYVINFO  - KDS service
	# Each of these is just appended to the otherinfo value used in
	# cryptography as the UTF-16-LE NULL terminated strings.
	kek_context = "KDS public key\0".encode("utf-16-le")
	secret = kdf_concat(
		secret_hash_algorithm,
		shared_secret,
		algorithm_id="SHA512\0".encode("utf-16-le"),
		party_uinfo=kek_context,
		party_vinfo=KDS_SERVICE_LABEL,
		length=secret_hash_algorithm.digest_size,
	)

	return kdf(
		algorithm,
		secret,
		KDS_SERVICE_LABEL,
		kek_context,
		32,
	)


def compute_public_key(
	secret_algorithm: str,
	secret_parameters: t.Optional[bytes],
	private_key: bytes,
	peer_public_key: bytes,
) -> bytes:
	if secret_algorithm == "DH":
		dh_pub_key = FFCDHKey.unpack(peer_public_key)

		# We can derive our public key based on the DH formula.
		# X = G**x mod p
		my_pub_key = pow(
			dh_pub_key.generator,
			int.from_bytes(private_key, byteorder="big"),
			dh_pub_key.field_order,
		)
		return FFCDHKey(
			dh_pub_key.key_length,
			dh_pub_key.field_order,
			dh_pub_key.generator,
			my_pub_key,
		).pack()

	elif secret_algorithm.startswith("ECDH_P"):
		ecdh_pub_key = ECDHKey.unpack(peer_public_key)
		curve = ecdh_pub_key.curve_and_hash[0]

		ecdh_private = ec.derive_private_key(
			int.from_bytes(private_key, byteorder="big"),
			curve,
		)
		my_ecdh_pub_key = ecdh_private.public_key().public_numbers()

		return ECDHKey(
			ecdh_pub_key.curve_name,
			ecdh_pub_key.key_length,
			my_ecdh_pub_key.x,
			my_ecdh_pub_key.y,
		).pack()

	else:
		raise NotImplementedError(f"Unknown secret agreement algorithm '{secret_algorithm}'")


class AlgorithmOID(str, enum.Enum):
	"""OIDs for cryptographic algorithms."""

	AES256_WRAP = "2.16.840.1.101.3.4.1.45"
	AES256_GCM = "2.16.840.1.101.3.4.1.46"

def cek_decrypt(
	algorithm: str,
	parameters: t.Optional[bytes],
	kek: bytes,
	value: bytes,
) -> bytes:
	if algorithm == 'aes256_wrap':
		return keywrap.aes_key_unwrap(kek, value)
	else:
		raise NotImplementedError(f"Unknown cek encryption algorithm OID '{algorithm}'")

def content_decrypt(
	algorithm: str,
	parameters: t.Optional[bytes],
	cek: bytes,
	value: bytes,
) -> bytes:
	if algorithm == 'aes256_gcm':
		if not parameters:
			raise ValueError("Expecting parameters for AES256 GCM decryption but received none.")

		iv = parameters['0']
		cipher = AESGCM(cek)
		return cipher.decrypt(iv, value, None)

	else:
		raise NotImplementedError(f"Unknown content encryption algorithm OID '{algorithm}'")

def decrypt_blob(
	blob: DPAPINGBlob,
	key: GroupKeyEnvelope,
) -> bytes:
	kek = key.get_kek(blob.key_identifier)

	# With the kek we can unwrap the encrypted cek in the LAPS payload.
	cek = cek_decrypt(
		blob.enc_cek_algorithm,
		blob.enc_cek_parameters,
		kek,
		blob.enc_cek,
	)

	# With the cek we can decrypt the encrypted content in the LAPS payload.
	return content_decrypt(
		blob.enc_content_algorithm,
		blob.enc_content_parameters,
		cek,
		blob.enc_content,
	)