class RiskProfiler:
    def __init__(self):
        self.sensitive_keywords = [
            "admin", "login", "auth", "token",
            "payment", "user", "update", "delete"
        ]

    def score(self, endpoint, method, requires_auth=False):
        risk = 0

        for keyword in self.sensitive_keywords:
            if keyword in endpoint.lower():
                risk += 2

        if method.upper() in ["POST", "PUT", "DELETE"]:
            risk += 2

        if requires_auth:
            risk += 2

        return risk

    def prioritize(self, endpoints):
        scored = []
        for ep in endpoints:
            score = self.score(
                ep["path"],
                ep.get("method", "GET"),
                ep.get("auth", False)
            )
            scored.append((ep, score))

        scored.sort(key=lambda x: x[1], reverse=True)
        return [ep for ep, _ in scored]