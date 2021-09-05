import asyncio
import traceback

class DCERPCServerSMBTransport:
	def __init__(self, smb_in_q, smb_out_q):
		self.smb_in_q = smb_in_q
		self.smb_out_q = smb_out_q
		self.in_q = None
		self.out_q = None

		self.__handle_incoming_task = None
		self.__handle_outgoing_task = None
	
	async def diconnect(self):
		if self.__handle_incoming_task is not None:
			self.__handle_incoming_task.cancel()
		if self.__handle_outgoing_task is not None:
			self.__handle_outgoing_task.cancel()

	async def __handle_incoming(self):
		try:
			while True:
				data = await self.smb_in_q.get()
				await self.in_q.put(data)

		except Exception as e:
			traceback.print_exc()
		finally:
			await self.diconnect()
	
	async def __handle_outgoing(self):
		try:
			while True:
				data = await self.out_q.get()
				await self.smb_out_q.put(data)

		except Exception as e:
			traceback.print_exc()
		finally:
			await self.diconnect()

	async def run(self):
		self.in_q = asyncio.Queue()
		self.out_q = asyncio.Queue()
		self.__handle_incoming_task = asyncio.create_task(self.__handle_incoming())
		self.__handle_outgoing_task = asyncio.create_task(self.__handle_outgoing())
