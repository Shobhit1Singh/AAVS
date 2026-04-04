import re
import hashlib
import math
from typing import Dict, List, Any
from colorama import Fore, Style

from analyser.vulnerability_rules import VulnerabilityRules
from detectors.authorisztion_detector import AuthorizationDetector


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
        r"pass",
        r"token",
        r"secret",
        r"key",
        r"auth",
        r"admin",
        r"role",
        r"ssn",
    ]

    DANGEROUS_HEADERS = {
        "X-Powered-By",
        "Server",
        "X-AspNet-Version",
        "X-AspNetMvc-Version",
    }

    def __init__(self):

        self.vulnerabilities: List[Dict[str, Any]] = []
        self.auth_detector = AuthorizationDetector()

        self.compiled_patterns = {
            t: [re.compile(p, re.IGNORECASE) for p in plist]
            for t, plist in self.ERROR_PATTERNS.items()
        }

        self.compiled_sensitive = [
            re.compile(p, re.IGNORECASE)
            for p in self.SENSITIVE_FIELD_PATTERNS
        ]

        self.endpoint_baselines = {}

    # -----------------------------
    # Utils
    # -----------------------------

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

    def _flatten_json_keys(self, obj, prefix=""):
        keys = []

        if isinstance(obj, dict):
            for k, v in obj.items():
                full = f"{prefix}.{k}" if prefix else k
                keys.append(full)
                keys += self._flatten_json_keys(v, full)

        elif isinstance(obj, list):
            for item in obj:
                keys += self._flatten_json_keys(item, prefix)

        return keys

    # -----------------------------
    # Baseline
    # -----------------------------

    def _update_baseline(self, endpoint_key, result):

        body = result.get("response_body", "")
        size = len(body)

        if endpoint_key not in self.endpoint_baselines:
            self.endpoint_baselines[endpoint_key] = {
                "sizes": [],
                "samples": [],
            }

        baseline = self.endpoint_baselines[endpoint_key]

        if len(baseline["sizes"]) < 5:
            baseline["sizes"].append(size)
            baseline["samples"].append(body[:500])

    # -----------------------------
    # MAIN ANALYSIS
    # -----------------------------

    def analyze_result(self, result: Dict[str, Any]) -> Dict[str, Any]:

        endpoint_key = f"{result.get('url')}_{result.get('method','')}"

        findings = []

        status_code = result.get("status_code", 0)
        body = result.get("response_body", "")
        headers = result.get("response_headers", {})
        payload = str(result.get("payload", ""))

        # -----------------------------
        # 1. PAYLOAD REFLECTION (CRITICAL)
        # -----------------------------
        if payload and payload.lower() in body.lower():
            findings.append({
                "type": "Payload Reflection (Possible XSS / Injection)",
                "severity": "CRITICAL"
            })

        # -----------------------------
        # 2. ERROR PATTERNS
        # -----------------------------
        for error_type, patterns in self.compiled_patterns.items():
            for pattern in patterns:
                if pattern.search(body):
                    findings.append({
                        "type": f"{error_type}",
                        "severity": "CRITICAL"
                    })
                    break

        # -----------------------------
        # 3. STATUS ANOMALY
        # -----------------------------
        if status_code >= 500:
            findings.append({
                "type": "Server Crash / Error Triggered",
                "severity": "HIGH"
            })

        # -----------------------------
        # 4. SENSITIVE DATA
        # -----------------------------
        for pattern in self.compiled_sensitive:
            if pattern.search(body):
                findings.append({
                    "type": "Sensitive Data Exposure",
                    "severity": "HIGH"
                })
                break

        # -----------------------------
        # 5. HEADER LEAK
        # -----------------------------
        for h in headers:
            if h in self.DANGEROUS_HEADERS:
                findings.append({
                    "type": "Tech Stack Disclosure",
                    "severity": "LOW"
                })

        # -----------------------------
        # 6. BASELINE DIFFERENCE (REAL ONE)
        # -----------------------------
        if endpoint_key in self.endpoint_baselines:

            baseline = self.endpoint_baselines[endpoint_key]

            for sample in baseline["samples"]:
                if sample != body[:500]:
                    findings.append({
                        "type": "Response Deviation",
                        "severity": "MEDIUM"
                    })
                    break

        # -----------------------------
        # 7. ENTROPY SPIKE
        # -----------------------------
        if self._entropy(body) > 5:
            findings.append({
                "type": "High Entropy Response (Possible Leak)",
                "severity": "MEDIUM"
            })

        # -----------------------------
        # 8. EXTERNAL RULES
        # -----------------------------
        findings.extend(VulnerabilityRules.run_all(result))

        # -----------------------------
        # FINAL DECISION (AGGRESSIVE)
        # -----------------------------
        if findings:

            result["vulnerability_detected"] = True
            result["vulnerabilities"] = findings

            self.vulnerabilities.append(result)

        else:
            result["vulnerability_detected"] = False

        self._update_baseline(endpoint_key, result)

        return result

    # -----------------------------
    # SUMMARY
    # -----------------------------

    def print_summary(self):

        print(f"\n{Fore.CYAN}{'='*60}")
        print("INTELLIGENT SCAN SUMMARY")
        print(f"{'='*60}{Style.RESET_ALL}")

        print(f"\nTotal Issues: {len(self.vulnerabilities)}")

        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")