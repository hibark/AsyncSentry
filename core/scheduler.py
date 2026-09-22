import asyncio


class CrawlScheduler:
    """
    Gère la file d'attente des URLs à explorer via asyncio.Queue,
    avec un pool de workers asynchrones consommant la queue.
    """

    def __init__(self, worker_count: int = 5):
        self.queue: asyncio.Queue = asyncio.Queue()
        self.worker_count = worker_count
        self.visited: set[str] = set()

    async def add(self, url: str, depth: int):
        """Ajoute une URL à la file si elle n'a pas déjà été visitée."""
        if url not in self.visited:
            self.visited.add(url)
            await self.queue.put((url, depth))

    async def run(self, handler):
        """
        Lance N workers qui consomment la queue en parallèle.
        `handler` est une coroutine appelée avec (url, depth) pour chaque item.
        """
        workers = [
            asyncio.create_task(self._worker(handler))
            for _ in range(self.worker_count)
        ]
        await self.queue.join()

        for w in workers:
            w.cancel()
        await asyncio.gather(*workers, return_exceptions=True)

    async def _worker(self, handler):
        while True:
            url, depth = await self.queue.get()
            try:
                await handler(url, depth)
            except Exception as e:
                print(f"[Scheduler Erreur] {url} -> {e}")
            finally:
                self.queue.task_done()