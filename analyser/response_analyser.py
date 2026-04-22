import re
import math
from typing import Dict, List, Any
from colorama import Fore, Style

from analyser.vulnerability_rules import VulnerabilityRules


class ResponseAnalyzer:

    ERROR_PATTERNS = {
        "sql_error": [
            r"SQL syntax",
            r"mysql_fetch",
            r"ORA-\d+",
            r"PostgreSQL.*ERROR",
            r"SQLite.*error",
            r"Microsoft SQL Server",
            r"ODBC.*Driver",
            r"syntax error at or near",
        ],
        "stack_trace": [
            r"Traceback \(most recent call last\)",
            r"Exception in thread",
            r"\.java:\d+\)",
        ],
        "path_disclosure": [
            r"[A-Z]:\\[\w\\]+",
            r"/var/www/",
            r"/home/[\w/]+",
            r"/usr/[\w/]+",
        ],
    }

    SENSITIVE_FIELD_PATTERNS = [
        r"password",
        r"token",
        r"secret",
        r"api[_-]?key",
        r"authorization",
    ]

    DANGEROUS_HEADERS = {
        "X-Powered-By",
        "Server",
        "X-AspNet-Version",
        "X-AspNetMvc-Version",
    }

    def __init__(self):

        self.vulnerabilities: List[Dict[str, Any]] = []

        self.compiled_patterns = {
            t: [re.compile(p, re.IGNORECASE) for p in plist]
            for t, plist in self.ERROR_PATTERNS.items()
        }

        self.compiled_sensitive = [
            re.compile(p, re.IGNORECASE)
            for p in self.SENSITIVE_FIELD_PATTERNS
        ]

        self.endpoint_baselines = {}

    # ======================================================
    # UTILS
    # ======================================================

    def _entropy(self, data: str):
        if not data:
            return 0

        freq = {}

        for c in data:
            freq[c] = freq.get(c, 0) + 1

        entropy = 0
        length = len(data)

        for f in freq.values():
            p = f / length
            entropy -= p * math.log2(p)

        return entropy

    # ======================================================
    # BASELINE
    # ======================================================

    def _update_baseline(self, endpoint_key, result):

        body = result.get("response_body", "")
        size = len(body)

        if endpoint_key not in self.endpoint_baselines:
            self.endpoint_baselines[endpoint_key] = {
                "sizes": [],
                "samples": [],
                "status_codes": []
            }

        baseline = self.endpoint_baselines[endpoint_key]

        if len(baseline["sizes"]) < 5:
            baseline["sizes"].append(size)
            baseline["samples"].append(body[:300])
            baseline["status_codes"].append(result.get("status_code"))

    def _is_deviation(self, endpoint_key, result):
        baseline = self.endpoint_baselines.get(endpoint_key)

        if not baseline:
            return False

        body = result.get("response_body", "")[:300]
        status = result.get("status_code")

        if status not in baseline["status_codes"]:
            return True

        for sample in baseline["samples"]:
            if sample == body:
                return False

        return True

    # ======================================================
    # MAIN ANALYSIS
    # ======================================================

    def analyze_result(self, result: Dict[str, Any]):

        endpoint = result.get("endpoint", "unknown")
        method = result.get("method", "GET")
        endpoint_key = f"{method}:{endpoint}"

        findings = []

        status_code = result.get("status_code", 0)
        body = result.get("response_body", "")
        headers = result.get("response_headers", {})
        payload = str(result.get("payload", "")).lower()

        # --------------------------------------------------
        # 1. Payload Reflection
        # --------------------------------------------------
        if payload and payload in body.lower():
            findings.append({
                "type": "Payload Reflection",
                "severity": "HIGH"
            })

        # --------------------------------------------------
        # 2. Error Patterns
        # --------------------------------------------------
        for error_type, patterns in self.compiled_patterns.items():
            for pattern in patterns:
                if pattern.search(body):
                    findings.append({
                        "type": error_type,
                        "severity": "CRITICAL"
                    })
                    break

        # --------------------------------------------------
        # 3. Server Errors
        # --------------------------------------------------
        if status_code >= 500:
            findings.append({
                "type": "Server Error Triggered",
                "severity": "HIGH"
            })

        # --------------------------------------------------
        # 4. Sensitive Data
        # --------------------------------------------------
        if status_code == 200:
            for pattern in self.compiled_sensitive:
                if pattern.search(body):
                    findings.append({
                        "type": "Sensitive Data Exposure",
                        "severity": "HIGH"
                    })
                    break

        # --------------------------------------------------
        # 5. Header Leakage
        # --------------------------------------------------
        for h in headers:
            if h in self.DANGEROUS_HEADERS:
                findings.append({
                    "type": "Tech Stack Disclosure",
                    "severity": "LOW"
                })

        # --------------------------------------------------
        # 6. Behavior Deviation
        # --------------------------------------------------
        if self._is_deviation(endpoint_key, result):
            findings.append({
                "type": "Behavior Change Detected",
                "severity": "MEDIUM"
            })

        # --------------------------------------------------
        # 7. Entropy Check
        # --------------------------------------------------
        if self._entropy(body) > 5.5:
            findings.append({
                "type": "High Entropy Response",
                "severity": "MEDIUM"
            })

        # --------------------------------------------------
        # 8. Auth Signals
        # --------------------------------------------------
        if status_code == 200 and "unauthorized" in body.lower():
            findings.append({
                "type": "Broken Auth Logic",
                "severity": "HIGH"
            })

        if status_code == 200 and "admin" in body.lower():
            findings.append({
                "type": "Possible Privilege Escalation",
                "severity": "HIGH"
            })

        # --------------------------------------------------
        # 9. External Rules
        # --------------------------------------------------
        findings.extend(VulnerabilityRules.run_all(result))

        # --------------------------------------------------
        # Final Save
        # --------------------------------------------------
        if findings:
            result["vulnerability_detected"] = True
            result["vulnerabilities"] = findings
            self.vulnerabilities.append(result)
        else:
            result["vulnerability_detected"] = False

        self._update_baseline(endpoint_key, result)

        return result

    # ======================================================
    # EXPORT FOR FRONTEND / RANKING
    # ======================================================

    def get_findings(self):
        """
        Convert raw analyzer detections into flat frontend-ready rows.
        Because apparently every layer wants a different format.
        """
        rows = []

        for item in self.vulnerabilities:

            endpoint = item.get("endpoint", "unknown")
            method = item.get("method", "GET")

            for vuln in item.get("vulnerabilities", []):

                rows.append({
                    "endpoint": endpoint,
                    "method": method,
                    "severity": vuln.get("severity", "LOW"),
                    "reason": vuln.get("type", "Issue Detected")
                })

        return rows

    # ======================================================
    # SUMMARY
    # ======================================================

    def print_summary(self):

        print(f"\n{Fore.CYAN}{'=' * 60}")
        print("INTELLIGENT SCAN SUMMARY")
        print(f"{'=' * 60}{Style.RESET_ALL}")

        print(f"\nTotal Issues: {len(self.vulnerabilities)}")

        print(f"\n{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}\n")