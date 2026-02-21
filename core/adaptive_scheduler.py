import asyncio
import heapq
from typing import Dict, List, Any, Set, Callable, Union
import json

class EndpointTask:
    def __init__(self, priority: int, endpoint: Dict[str, Any]):
        self.priority = priority
        self.endpoint = endpoint

    def __lt__(self, other):
        return self.priority < other.priority


class AdaptiveScheduler:
    def __init__(
        self,
        max_concurrency: int = 20,
        waf_safe_concurrency: int = 5,
    ):
        self.fast_mode = True
        self.max_concurrency = max_concurrency
        self.min_concurrency = waf_safe_concurrency
        self.current_concurrency = max_concurrency
        self.sem = asyncio.Semaphore(self.current_concurrency)
        self.queue: List[EndpointTask] = []
        self.visited_payloads: Set[str] = set()

    # ---------------------------
    # Risk scoring
    # ---------------------------
    def score_endpoint(self, endpoint: Dict[str, Any]) -> int:
        score = 100
        path = endpoint.get("path", "").lower()
        method = endpoint.get("method", "").upper()
        risky_keywords = ["login", "auth", "token", "user", "admin", "password"]
        for word in risky_keywords:
            if word in path:
                score -= 30
        if method in ["POST", "PUT", "PATCH"]:
            score -= 20
        params = endpoint.get("params", [])
        score -= len(params) * 2
        return max(score, 1)

    # ---------------------------
    # Queue management
    # ---------------------------
    def add_endpoints(self, endpoints: List[Dict[str, Any]]):
        for ep in endpoints:
            priority = self.score_endpoint(ep)
            heapq.heappush(self.queue, EndpointTask(priority, ep))

    def get_next(self) -> Union[Dict[str, Any], None]:
        if not self.queue:
            return None
        return heapq.heappop(self.queue).endpoint

    # ---------------------------
    # Payload deduplication
    # ---------------------------
    def should_test_payload(self, payload_id: str) -> bool:
        if payload_id in self.visited_payloads:
            return False
        self.visited_payloads.add(payload_id)
        return True

    # ---------------------------
    # Concurrency adaptation
    # ---------------------------
    def reduce_concurrency(self):
        new_level = max(self.current_concurrency // 2, self.min_concurrency)
        if new_level != self.current_concurrency:
            self.current_concurrency = new_level
            self.sem = asyncio.Semaphore(self.current_concurrency)

    def increase_concurrency(self):
        new_level = min(self.current_concurrency + 2, self.max_concurrency)
        if new_level != self.current_concurrency:
            self.current_concurrency = new_level
            self.sem = asyncio.Semaphore(self.current_concurrency)

    # ---------------------------
    # Scan phase control
    # ---------------------------
    def switch_to_deep_scan(self):
        self.fast_mode = False

    # ---------------------------
    # Main async runner
    # ---------------------------
    async def run(
        self,
        executor_func: Callable,
        analyzer_func: Callable,
        waf_detector_func: Callable,
        attack_generator_func: Callable,
        retry_engine: Any,
    ):
        tasks = []

        while self.queue:
            endpoint = self.get_next()
            if not endpoint:
                break

            await self.sem.acquire()
            task = asyncio.create_task(
                self._process_endpoint(
                    endpoint,
                    executor_func,
                    analyzer_func,
                    waf_detector_func,
                    attack_generator_func,
                    retry_engine,
                )
            )
            task.add_done_callback(lambda t: self.sem.release())
            tasks.append(task)

        await asyncio.gather(*tasks)

    # ---------------------------
    # Endpoint processing logic
    # ---------------------------
    async def _process_endpoint(
        self,
        endpoint: Dict[str, Any],
        executor_func: Callable,
        analyzer_func: Callable,
        waf_detector_func: Callable,
        attack_generator_func: Callable,
        retry_engine: Any,
    ):
        payloads = attack_generator_func(endpoint, fast_mode=self.fast_mode)

        for payload in payloads:
            # Create a unique ID for deduplication
            if isinstance(payload, dict):
                payload_repr = json.dumps(payload, sort_keys=True)
            else:
                payload_repr = str(payload)

            payload_id = f"{endpoint['path']}::{payload_repr}"

            if not self.should_test_payload(payload_id):
                continue

            # 🔥 Intelligent adaptive retry execution
            response = await retry_engine.execute_with_retry(
                executor_func,
                endpoint,
                payload,
            )

            # Adaptive concurrency based on WAF signals
            if waf_detector_func(response):
                self.reduce_concurrency()
            else:
                self.increase_concurrency()

            # Analyze result
            vuln_found = analyzer_func(response)

            # Switch to deep scan if vulnerability detected
            if vuln_found:
                self.switch_to_deep_scan()