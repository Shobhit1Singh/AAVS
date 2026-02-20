import asyncio
import time


class IntelligencePipeline:

    def __init__(self, waf_manager, scheduler, analyzer=None):
        self.waf_manager = waf_manager
        self.scheduler = scheduler
        self.analyzer = analyzer

        self.response_queue = asyncio.Queue()
        self.running = False

        self.waf_hits = 0
        self.last_reset = time.time()

    async def start(self):
        self.running = True
        asyncio.create_task(self._process_loop())

    async def stop(self):
        self.running = False

    async def submit_response(self, response):
        await self.response_queue.put(response)

    async def _process_loop(self):
        while self.running:
            response = await self.response_queue.get()

            waf_detected = self.waf_manager.detect_waf(response)

            if waf_detected:
                self.waf_hits += 1

            if self.analyzer:
                self.analyzer(response)

            await self._adaptive_control()

            self.response_queue.task_done()

    async def _adaptive_control(self):
        now = time.time()

        if now - self.last_reset < 3:
            return

        hit_rate = self.waf_hits

        if hit_rate > 10:
            self.scheduler.reduce_concurrency()

        elif hit_rate == 0:
            self.scheduler.increase_concurrency()

        self.waf_hits = 0
        self.last_reset = now