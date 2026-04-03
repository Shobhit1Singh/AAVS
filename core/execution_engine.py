import json


class ExecutionEngine:

    def __init__(self, executor, memory):
        self.executor = executor
        self.memory = memory
        self.baselines = {}

    def _normalize(self, result):
        if result is None:
            return None

        normalized = {
            "status_code": getattr(result, "status_code", None),
            "response_body": getattr(result, "body", ""),
            "response_headers": getattr(result, "headers", {}),
            "response_time": getattr(result, "response_time", 0),
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

        response = await self.executor.execute(endpoint, {})
        if not response:
            return None

        baseline = self._normalize(response)
        self.baselines[key] = baseline

        self.memory.register_endpoint(
            endpoint["method"],
            endpoint["path"],
            {"has_json": baseline.get("json") is not None}
        )

        return baseline

    async def execute(self, endpoint, payload):
        response = await self.executor.execute(endpoint, payload)
        if not response:
            return None

        return self._normalize(response)