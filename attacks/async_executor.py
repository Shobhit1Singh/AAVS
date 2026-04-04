import asyncio
import aiohttp
import time


class BaseExecutor:
    async def execute(self, endpoint, payload):
        raise NotImplementedError("Executor must implement execute()")


class RealHTTPExecutor(BaseExecutor):
    def __init__(self, base_url, max_concurrency=20, timeout=10):
        self.base_url = base_url.rstrip("/")
        self.semaphore = asyncio.Semaphore(max_concurrency)
        self.timeout = aiohttp.ClientTimeout(total=timeout)

    async def execute(self, endpoint, payload):
        async with self.semaphore:

            path = endpoint.get("path", "")
            method = endpoint.get("method", "GET").upper()

            url = f"{self.base_url}{path}"

            headers = {}
            params = {}
            json_body = None

            # ----------------------------
            # PAYLOAD INTERPRETATION (FIXED PROPERLY)
            # ----------------------------
            if isinstance(payload, dict):

                # 1. Direct structured payload support (preferred)
                headers.update(payload.get("headers", {}))
                params.update(payload.get("params", {}))

                if "body" in payload:
                    json_body = payload["body"]

                # 2. Backward compatibility (your old broken format)
                param_location = payload.get("param_location")
                param_name = payload.get("param_name")
                value = payload.get("payload")

                if param_location and param_name:

                    if param_location == "query":
                        params[param_name] = value

                    elif param_location == "header":
                        headers[param_name] = str(value)

                    elif param_location == "path":
                        url = url.replace(f"{{{param_name}}}", str(value))

                    elif param_location == "body":
                        json_body = {param_name: value}

                # 3. Full body override (highest priority)
                if "full_body" in payload:
                    json_body = payload["full_body"]

                # 4. Path params (NEW - critical for /user/{id})
                if "path_params" in payload:
                    for k, v in payload["path_params"].items():
                        url = url.replace(f"{{{k}}}", str(v))

            # ----------------------------
            # DEBUG
            # ----------------------------
            print("\n=== HTTP DEBUG ===")
            print("METHOD:", method)
            print("URL:", url)
            print("HEADERS:", headers)
            print("PARAMS:", params)
            print("BODY:", json_body)

            try:
                start = time.time()

                async with aiohttp.ClientSession(timeout=self.timeout) as session:
                    async with session.request(
                        method=method,
                        url=url,
                        params=params if params else None,
                        json=json_body if method in ["POST", "PUT", "PATCH"] else None,
                        headers=headers,
                    ) as resp:

                        body = await resp.text()
                        elapsed = time.time() - start

                        print("STATUS:", resp.status)
                        print("RESPONSE:", body[:200])
                        print("=================\n")

                        return {
                            "status_code": resp.status,
                            "response_body": body,
                            "response_headers": dict(resp.headers),
                            "response_time": elapsed,
                            "url": str(resp.url),
                        }

            except asyncio.TimeoutError:
                print("TIMEOUT\n")
                return {
                    "status_code": 0,
                    "response_body": "",
                    "response_headers": {},
                    "response_time": self.timeout.total,
                    "error": "Timeout",
                }

            except Exception as e:
                print("ERROR:", str(e), "\n")
                return {
                    "status_code": 0,
                    "response_body": "",
                    "response_headers": {},
                    "response_time": 0,
                    "error": str(e),
                }


class MockExecutor(BaseExecutor):
    async def execute(self, endpoint, payload):

        payload_str = str(payload)

        if "' OR '1'='1'" in payload_str or "UNION SELECT" in payload_str:
            return {
                "status_code": 500,
                "response_body": "Internal Server Error",
                "response_headers": {},
                "response_time": 0.01,
            }

        return {
            "status_code": 200,
            "response_body": "OK",
            "response_headers": {},
            "response_time": 0.01,
        }


class ReplayExecutor(BaseExecutor):
    def __init__(self, recorded_responses):
        self.recorded_responses = recorded_responses

    async def execute(self, endpoint, payload):
        for item in self.recorded_responses:
            if item.get("endpoint") == endpoint.get("path"):
                return item

        return {
            "status_code": 404,
            "response_body": "",
            "response_headers": {},
            "response_time": 0,
        }


# ----------------------------
# TEST RUN
# ----------------------------
if __name__ == "__main__":
    async def main():
        executor = RealHTTPExecutor("http://localhost:3000")

        endpoint = {"path": "/api/search", "method": "GET"}

        payload = {
            "params": {"q": "<script>alert(1)</script>"}
        }

        result = await executor.execute(endpoint, payload)

        print(result)

    asyncio.run(main())