import asyncio
import aiohttp
import time


class Response:
    def __init__(
        self,
        endpoint,
        payload,
        status_code,
        body,
        headers,
        response_time,
        error=None,
    ):
        self.endpoint = endpoint
        self.payload = payload
        self.status_code = status_code
        self.body = body
        self.headers = headers
        self.response_time = response_time
        self.error = error

    def to_dict(self):
        return {
            "endpoint": self.endpoint,
            "payload": self.payload,
            "status_code": self.status_code,
            "response_body": self.body,
            "response_headers": self.headers,
            "response_time": self.response_time,
            "error": self.error,
        }


class BaseExecutor:
    async def run_tests(self, endpoints, payloads):
        raise NotImplementedError("Executor must implement run_tests()")


class RealHTTPExecutor(BaseExecutor):
    def __init__(self, base_url, max_concurrency=20, timeout=10):
        self.base_url = base_url.rstrip("/")
        self.semaphore = asyncio.Semaphore(max_concurrency)
        self.timeout = timeout

    async def _send_request(self, session, endpoint, payload):
        async with self.semaphore:
            url = f"{self.base_url}{endpoint['path']}"
            method = endpoint.get("method", "POST").upper()
            headers = endpoint.get("headers", {})

            try:
                start = time.time()
                async with session.request(
                    method,
                    url,
                    json=payload,
                    headers=headers,
                    timeout=self.timeout,
                ) as resp:
                    body = await resp.text()
                    elapsed = time.time() - start

                    return Response(
                        endpoint=endpoint["path"],
                        payload=payload,
                        status_code=resp.status,
                        body=body,
                        headers=dict(resp.headers),
                        response_time=elapsed,
                    )

            except asyncio.TimeoutError:
                return Response(
                    endpoint=endpoint["path"],
                    payload=payload,
                    status_code=0,
                    body="",
                    headers={},
                    response_time=self.timeout,
                    error="Timeout",
                )

            except Exception as e:
                return Response(
                    endpoint=endpoint["path"],
                    payload=payload,
                    status_code=0,
                    body="",
                    headers={},
                    response_time=0,
                    error=str(e),
                )

    async def run_tests(self, endpoints, payloads):
        async with aiohttp.ClientSession() as session:
            tasks = []
            for ep in endpoints:
                for pl in payloads:
                    tasks.append(self._send_request(session, ep, pl))
            return await asyncio.gather(*tasks)


class MockExecutor(BaseExecutor):
    async def run_tests(self, endpoints, payloads):
        results = []

        for ep in endpoints:
            for pl in payloads:
                payload_str = str(pl)

                if "' OR '1'='1'" in payload_str or "UNION SELECT" in payload_str:
                    status = 500
                    body = "Internal Server Error"
                else:
                    status = 200
                    body = "OK"

                results.append(
                    Response(
                        endpoint=ep["path"],
                        payload=pl,
                        status_code=status,
                        body=body,
                        headers={},
                        response_time=0.01,
                    )
                )

        return results


class ReplayExecutor(BaseExecutor):
    def __init__(self, recorded_responses):
        self.recorded_responses = recorded_responses

    async def run_tests(self, endpoints, payloads):
        responses = []
        for item in self.recorded_responses:
            responses.append(
                Response(
                    endpoint=item["endpoint"],
                    payload=item["payload"],
                    status_code=item["status_code"],
                    body=item["response_body"],
                    headers=item["response_headers"],
                    response_time=item["response_time"],
                    error=item.get("error"),
                )
            )
        return responses


# Example usage
if __name__ == "__main__":
    endpoints = [
        {"path": "/rest/user/login", "method": "POST"},
        {"path": "/rest/product", "method": "GET"},
    ]

    payloads = [
        {"username": "' OR '1'='1' /*", "password": "test"},
        {"username": "admin", "password": "admin"},
    ]

    mode = "mock"  # change to "live" for real HTTP

    if mode == "live":
        executor = RealHTTPExecutor("http://localhost:3000")
    else:
        executor = MockExecutor()

    results = asyncio.run(executor.run_tests(endpoints, payloads))

    for r in results:
        print(r.to_dict())