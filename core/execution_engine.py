import json


class ExecutionEngine:

    def __init__(self, executor, memory):
        self.executor = executor
        self.memory = memory
        self.baselines = {}

    def _normalize(self, result):
        if result is None:
            return None

        if isinstance(result, dict):
            return result

        normalized = {
            "status_code": getattr(result, "status", None),
            "response_body": getattr(result, "text", ""),
            "response_headers": dict(getattr(result, "headers", {})),
            "url": str(getattr(result, "url", "")),
        }

        try:
            normalized["json"] = json.loads(normalized["response_body"])
        except:
            normalized["json"] = None

        return normalized

    async def get_baseline(self, endpoint):
        key = f"{endpoint['method']}:{endpoint['path']}"
        if key in self.baselines:
            return self.baselines[key]

        responses = await self.executor.run_tests([endpoint], [{}])
        if not responses:
            return None

        baseline = self._normalize(responses[0])
        self.baselines[key] = baseline

        self.memory.register_endpoint(
            endpoint["method"],
            endpoint["path"],
            {"has_json": baseline.get("json") is not None}
        )

        return baseline

    async def execute(self, endpoint, payload):
        responses = await self.executor.run_tests([endpoint], [payload])
        if not responses:
            return None
        return self._normalize(responses[0])