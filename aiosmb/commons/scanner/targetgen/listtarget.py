

import asyncio
import uuid


class ListTargetGen:
	def __init__(self, targets):
		self.targets = targets

	async def run(self, target_q):
		try:
			cnt = 0
			for target in self.targets:
				cnt += 1
				await target_q.put((str(uuid.uuid4()),target))
				await asyncio.sleep(0)
			return cnt, None
		except Exception as e:
			return cnt, e