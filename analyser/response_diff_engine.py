import re


class ResponseDiffEngine:

    ERROR_KEYWORDS = [
        "sql",
        "syntax",
        "exception",
        "traceback",
        "stack",
        "error",
        "warning"
    ]

    def compare(self, baseline, attack):

        findings = []

        base_len = len(baseline)
        attack_len = len(attack)

        # Length difference detection
        if abs(base_len - attack_len) > 50:
            findings.append("SIGNIFICANT_LENGTH_CHANGE")

        # New error detection
        attack_lower = attack.lower()
        base_lower = baseline.lower()

        for keyword in self.ERROR_KEYWORDS:
            if keyword in attack_lower and keyword not in base_lower:
                findings.append(f"NEW_ERROR_PATTERN:{keyword}")

        # Data leakage detection (simple heuristic)
        if re.search(r'\b\d{12,16}\b', attack):
            findings.append("POSSIBLE_SENSITIVE_DATA_LEAK")

        return findings