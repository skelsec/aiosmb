"""Queue-backed byte-stream adapter for one SMB named-pipe instance."""

import asyncio
from typing import Optional


class DCERPCServerSMBTransport:
	"""Adapt two queues to a deterministic per-pipe byte stream.

	Each instance represents one opened named pipe.  Queue records may be split
	or coalesced by callers; ``read`` and ``readexactly`` retain unconsumed bytes
	without depending on SMB server connection objects.
	"""

	def __init__(
		self,
		smb_in_q=None,
		smb_out_q=None,
		pipe_name: Optional[str] = None,
		max_write_size: Optional[int] = None,
	):
		if max_write_size is not None and max_write_size <= 0:
			raise ValueError('max_write_size must be positive')
		self.smb_in_q = smb_in_q if smb_in_q is not None else asyncio.Queue()
		self.smb_out_q = smb_out_q if smb_out_q is not None else asyncio.Queue()
		# Preserve the original queue-oriented public names.
		self.in_q = self.smb_in_q
		self.out_q = self.smb_out_q
		self.pipe_name = pipe_name
		self.max_write_size = max_write_size
		self._read_buffer = bytearray()
		self._read_lock = asyncio.Lock()
		self._write_lock = asyncio.Lock()
		self._eof = False
		self._closed = False

	async def run(self):
		"""Compatibility no-op; the adapter needs no background tasks."""

		return self

	async def feed_data(self, data):
		"""Append bytes, or ``None`` for EOF, to this pipe's input."""

		if self._closed:
			raise RuntimeError('transport is closed')
		if data is not None and not isinstance(
			data, (bytes, bytearray, memoryview)
		):
			raise TypeError('SMB pipe input must be bytes or None')
		await self.smb_in_q.put(None if data is None else bytes(data))

	async def feed_eof(self):
		await self.feed_data(None)

	async def _next_input(self):
		if self._eof:
			return None
		data = await self.smb_in_q.get()
		if data is None:
			self._eof = True
			return None
		if not isinstance(data, (bytes, bytearray, memoryview)):
			raise TypeError('SMB pipe queue records must be bytes or None')
		return bytes(data)

	async def read(self, size: int = -1):
		"""Read bytes from the pipe, returning ``None`` only at clean EOF.

		With a positive size, the method returns exactly that many bytes unless
		EOF is reached.  With the default size, it returns the currently buffered
		bytes or one complete input queue record.
		"""

		if size == 0:
			return b''
		if size < -1:
			raise ValueError('read size must be -1 or non-negative')

		async with self._read_lock:
			if size == -1:
				if not self._read_buffer:
					data = await self._next_input()
					if data is None:
						return None
					self._read_buffer.extend(data)
				data = bytes(self._read_buffer)
				self._read_buffer.clear()
				return data

			while len(self._read_buffer) < size and not self._eof:
				data = await self._next_input()
				if data is None:
					break
				self._read_buffer.extend(data)

			if not self._read_buffer and self._eof:
				return None
			data = bytes(self._read_buffer[:size])
			del self._read_buffer[:size]
			return data

	async def readexactly(self, size: int) -> bytes:
		"""Read exactly ``size`` bytes or raise ``IncompleteReadError``."""

		if size < 0:
			raise ValueError('readexactly size must be non-negative')
		data = await self.read(size)
		if data is None:
			data = b''
		if len(data) != size:
			raise asyncio.IncompleteReadError(data, size)
		return data

	async def write(self, data: bytes) -> int:
		"""Write bytes in deterministic records and return the byte count."""

		if self._closed:
			raise RuntimeError('transport is closed')
		if not isinstance(data, (bytes, bytearray, memoryview)):
			raise TypeError('SMB pipe output must be bytes')
		data = bytes(data)

		async with self._write_lock:
			if self.max_write_size is None or not data:
				await self.smb_out_q.put(data)
			else:
				for offset in range(0, len(data), self.max_write_size):
					await self.smb_out_q.put(
						data[offset:offset + self.max_write_size]
					)
		return len(data)

	async def send(self, data):
		"""Compatibility wrapper using the client transport return convention."""

		try:
			await self.write(data)
			return True, None
		except Exception as error:
			return None, error

	async def recv(self, count=1):
		"""Compatibility wrapper using the client transport return convention."""

		try:
			data = await self.read()
			return data, None
		except Exception as error:
			return None, error

	async def disconnect(self):
		if self._closed:
			return
		self._closed = True
		self._read_buffer.clear()
		if not self._eof:
			await self.smb_in_q.put(None)

	async def diconnect(self):
		"""Backward-compatible alias for the historical misspelling."""

		await self.disconnect()
