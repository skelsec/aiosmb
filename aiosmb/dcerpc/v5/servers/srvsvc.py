import traceback
import asyncio


class SRVSVCServer:
	def __init__(self, transport):
		self.transport = None
		self.__incoming_task = None

	async def __handle_incoming(self):
		try:
			while True:
				msg = await self.transport.in_q.get()
				print(msg)

		except Exception as e:
			traceback.print_exc()

	async def run(self):
		self.__incoming_task = asyncio.create_task(self.__handle_incoming())