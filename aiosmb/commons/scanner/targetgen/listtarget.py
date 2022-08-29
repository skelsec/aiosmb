

import asyncio
import uuid


class ListTargetGen:
	def __init__(self, targets, with_id = False):
		self.targets = targets
		self.with_id = with_id

	async def run(self, target_q):
		try:
			cnt = 0
			for tres in self.targets:
				if self.with_id is True:
					tid, target = tres
				else:
					tid = str(uuid.uuid4())
					target = tres
				cnt += 1
				await target_q.put((tid,target))
				await asyncio.sleep(0)
			return cnt, None
		except Exception as e:
			return cnt, e
	
	