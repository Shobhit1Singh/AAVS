class SemanticDiffEngine:

    def compare(self, base_response, test_response):
        issues = []

        if not base_response or not test_response:
            return issues

        base_text = base_response.get("text", "")
        test_text = test_response.get("text", "")

        # 1️⃣ Response size anomaly
        if abs(len(test_text) - len(base_text)) > 200:
            issues.append("Response size anomaly detected")

        # 2️⃣ JSON structure changes
        base_json = base_response.get("json")
        test_json = test_response.get("json")

        if isinstance(base_json, dict) and isinstance(test_json, dict):
            new_keys = set(test_json.keys()) - set(base_json.keys())
            if new_keys:
                issues.append(f"New fields exposed: {list(new_keys)}")

        # 3️⃣ Status code difference intelligence
        if base_response.get("status") != test_response.get("status"):
            issues.append(
                f"Status code changed: {base_response.get('status')} → {test_response.get('status')}"
            )

        return issues