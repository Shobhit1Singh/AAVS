class AuthorizationDetector:
    def __init__(self):
        self.sensitive_keywords = {
            "password",
            "token",
            "secret",
            "email",
            "role",
            "isAdmin",
            "admin",
            "userId",
            "accountId"
        }

    def analyze(self, baseline_response, mutated_response, diff_object, metadata=None):
        result = {
            "vulnerability": "Broken Object Level Authorization",
            "confidence": 0.0,
            "signals": [],
            "evidence": {}
        }

        if not isinstance(baseline_response, dict) or not isinstance(mutated_response, dict):
            return None

        confidence = 0.0

        added_fields = diff_object.get("added_fields", [])
        changed_values = diff_object.get("changed_values", [])
        array_growth = diff_object.get("array_growth", 0)

        if added_fields:
            confidence += 0.2
            result["signals"].append("New fields exposed after tampering")
            result["evidence"]["added_fields"] = added_fields

        sensitive_exposed = []
        for field in added_fields:
            if any(keyword.lower() in field.lower() for keyword in self.sensitive_keywords):
                sensitive_exposed.append(field)

        if sensitive_exposed:
            confidence += 0.4
            result["signals"].append("Sensitive fields exposed")
            result["evidence"]["sensitive_fields"] = sensitive_exposed

        if changed_values:
            confidence += 0.2
            result["signals"].append("Existing fields changed unexpectedly")
            result["evidence"]["changed_fields"] = changed_values

        if array_growth > 0:
            confidence += 0.2
            result["signals"].append("Response array size increased")
            result["evidence"]["array_growth"] = array_growth

        if baseline_response.get("id") != mutated_response.get("id"):
            confidence += 0.2
            result["signals"].append("Object identifier mismatch without access control error")
            result["evidence"]["baseline_id"] = baseline_response.get("id")
            result["evidence"]["mutated_id"] = mutated_response.get("id")

        if confidence >= 0.3:
            result["confidence"] = min(confidence, 1.0)
            return result

        return None