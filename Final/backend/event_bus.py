import asyncio
from typing import List

from schemas import SentraEvent


class EventBus:
    def __init__(self):
        self.subscribers: List[asyncio.Queue] = []

    async def publish(self, event: SentraEvent):
        dead_subscribers = []

        for queue in self.subscribers:
            try:
                queue.put_nowait(event)
            except Exception:
                dead_subscribers.append(queue)

        for queue in dead_subscribers:
            if queue in self.subscribers:
                self.subscribers.remove(queue)

    def subscribe(self) -> asyncio.Queue:
        queue = asyncio.Queue(maxsize=100)
        self.subscribers.append(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue):
        if queue in self.subscribers:
            self.subscribers.remove(queue)


event_bus = EventBus()