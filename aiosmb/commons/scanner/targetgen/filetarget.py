
import asyncio
import uuid

class FileTargetGen:
	def __init__(self, filename):
		self.filename = filename

	async def run(self, target_q):
		try:
			cnt = 0
			with open(self.filename, 'r') as f:
				for line in f:
					line = line.strip()
					await target_q.put((str(uuid.uuid4()), line))
					await asyncio.sleep(0)
			return cnt, None
		except Exception as e:
			return cnt, e