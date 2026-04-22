class SeverityEngine:

    SEVERITY_MAP = {
        "CRITICAL": 9,
        "HIGH": 7,
        "MEDIUM": 5,
        "LOW": 1,
        "INFO": 3
    }

    def __init__(self):
        self.endpoint_scores = {}

    def process(self, result):
        endpoint = result.get("endpoint", "unknown")
        method = result.get("method", "GET")

        key = f"{method} {endpoint}"

        if key not in self.endpoint_scores:
            self.endpoint_scores[key] = {
                "score": 0,
                "issues": []
            }

        # CASE 1: flat finding
        if "severity" in result:
            severity = result.get("severity", "INFO")
            score = self.SEVERITY_MAP.get(severity, 1)

            self.endpoint_scores[key]["score"] += score
            self.endpoint_scores[key]["issues"].append(result)
            return

        # CASE 2: nested vulnerabilities list
        for vuln in result.get("vulnerabilities", []):
            severity = vuln.get("severity", "INFO")
            score = self.SEVERITY_MAP.get(severity, 1)

            self.endpoint_scores[key]["score"] += score
            self.endpoint_scores[key]["issues"].append(vuln)

    def get_ranked(self):
        return sorted(
            self.endpoint_scores.items(),
            key=lambda x: x[1]["score"],
            reverse=True
        )

    def print_ranking(self):
        print("\n" + "=" * 60)
        print("RISK RANKING")
        print("=" * 60)

        ranked = self.get_ranked()

        if not ranked:
            print("No ranked endpoints available")

        for endpoint, data in ranked:
            print(f"{endpoint:40} -> Score: {data['score']}")

        print("=" * 60 + "\n")