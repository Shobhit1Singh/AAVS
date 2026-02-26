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

        self.seen_hashes = set()

        self.endpoint_baselines = {}

    # -------------------------------------------------------
    # Utility
    # -------------------------------------------------------

    def _fingerprint(self, result):
        return hashlib.md5(
            (result.get("response_body", "")[:500] +
             str(result.get("status_code"))).encode()
        ).hexdigest()

    def _shannon_entropy(self, data: str) -> float:
        if not data:
            return 0.0
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
            for i, item in enumerate(obj):
                keys += self._flatten_json_keys(item, prefix)
        return keys

    # -------------------------------------------------------
    # Baseline Modeling
    # -------------------------------------------------------

    def _update_baseline(self, endpoint_key, result):
        body = result.get("response_body", "")
        size = len(body)
        time = result.get("response_time", 0)
        json_body = result.get("json")

        keys = self._flatten_json_keys(json_body) if json_body else []

        if endpoint_key not in self.endpoint_baselines:
            self.endpoint_baselines[endpoint_key] = {
                "sizes": [],
                "times": [],
                "keys": set(),
                "entropy": []
            }

        baseline = self.endpoint_baselines[endpoint_key]
        baseline["sizes"].append(size)
        baseline["times"].append(time)
        baseline["entropy"].append(self._shannon_entropy(body[:2000]))
        baseline["keys"].update(keys)

    # -------------------------------------------------------
    # Intelligent Analysis
    # -------------------------------------------------------

    def analyze_result(self, result: Dict[str, Any]) -> Dict[str, Any]:

        fingerprint = self._fingerprint(result)
        if fingerprint in self.seen_hashes:
            return result
        self.seen_hashes.add(fingerprint)

        endpoint_key = f"{result.get('url')}_{result.get('method', '')}"

        findings = []
        confidence = 0

        status_code = result.get("status_code", 0)
        body = result.get("response_body", "")[:2000]
        headers = result.get("response_headers", {})
        response_time = result.get("response_time", 0)
        json_body = result.get("json")

        # -------------------------
        # Pattern Detection
        # -------------------------
        for error_type, patterns in self.compiled_patterns.items():
            for pattern in patterns:
                match = pattern.search(body)
                if match:
                    findings.append({
                        "type": f"Information Disclosure ({error_type})",
                        "severity": "CRITICAL" if error_type == "sql_error" else "HIGH",
                        "evidence": body[max(0, match.start()-50):match.end()+50],
                    })
                    confidence += 3
                    break

        # -------------------------
        # Sensitive Field Detection
        # -------------------------
        if json_body:
            keys = self._flatten_json_keys(json_body)
            for key in keys:
                for pattern in self.compiled_sensitive:
                    if pattern.search(key):
                        findings.append({
                            "type": "Sensitive Field Exposure",
                            "severity": "CRITICAL",
                            "field": key
                        })
                        confidence += 4
                        break

        # -------------------------
        # Statistical Deviation
        # -------------------------
        if endpoint_key in self.endpoint_baselines:
            baseline = self.endpoint_baselines[endpoint_key]

            avg_size = sum(baseline["sizes"]) / len(baseline["sizes"])
            if abs(len(body) - avg_size) > avg_size * 0.4:
                findings.append({
                    "type": "Structural Size Anomaly",
                    "severity": "MEDIUM"
                })
                confidence += 2

            avg_time = sum(baseline["times"]) / len(baseline["times"])
            if response_time > avg_time * 2:
                findings.append({
                    "type": "Timing Anomaly",
                    "severity": "MEDIUM"
                })
                confidence += 2

            entropy_now = self._shannon_entropy(body)
            avg_entropy = sum(baseline["entropy"]) / len(baseline["entropy"])
            if entropy_now > avg_entropy + 1.0:
                findings.append({
                    "type": "High Entropy Data Exposure",
                    "severity": "HIGH"
                })
                confidence += 3

            if json_body:
                new_keys = set(self._flatten_json_keys(json_body))
                unexpected = new_keys - baseline["keys"]
                if unexpected:
                    findings.append({
                        "type": "Unexpected JSON Fields",
                        "severity": "HIGH",
                        "fields": list(unexpected)
                    })
                    confidence += 3

        # -------------------------
        # Dangerous Headers
        # -------------------------
        exposed = self.DANGEROUS_HEADERS.intersection(headers.keys())
        for h in exposed:
            findings.append({
                "type": "Sensitive Header Exposure",
                "severity": "LOW",
                "header": h
            })
            confidence += 1

        # -------------------------
        # Status Code Intelligence
        # -------------------------
        if status_code == 500:
            findings.append({
                "type": "Server Error Triggered",
                "severity": "HIGH"
            })
            confidence += 2

        # -------------------------
        # External Rules
        # -------------------------
        rule_findings = VulnerabilityRules.run_all(result)
        if rule_findings:
            findings.extend(rule_findings)
            confidence += 3

        # -------------------------
        # Decision Engine
        # -------------------------
        if confidence >= 3:
            result["vulnerability_detected"] = True
            result["vulnerabilities"] = findings
            result["confidence_score"] = confidence
            self.vulnerabilities.append(result)
        else:
            result["vulnerability_detected"] = False

        # Update baseline after evaluation
        self._update_baseline(endpoint_key, result)

        return result

    # -------------------------------------------------------
    # Differential Authorization
    # -------------------------------------------------------

    def analyze_authorization(
        self,
        baseline_result: Dict[str, Any],
        mutated_result: Dict[str, Any],
        diff_object: Dict[str, Any],
        metadata: Dict[str, Any] = None
    ) -> Dict[str, Any]:

        baseline_body = baseline_result.get("json")
        mutated_body = mutated_result.get("json")

        auth_finding = self.auth_detector.analyze(
            baseline_body,
            mutated_body,
            diff_object,
            metadata
        )

        if auth_finding:
            mutated_result["vulnerability_detected"] = True
            mutated_result.setdefault("vulnerabilities", []).append(auth_finding)
            self.vulnerabilities.append(mutated_result)

        return mutated_result

    # -------------------------------------------------------
    # Stats
    # -------------------------------------------------------

    def get_statistics(self) -> Dict[str, Any]:
        stats = {"total": len(self.vulnerabilities), "severity": {}}

        for v in self.vulnerabilities:
            for item in v.get("vulnerabilities", []):
                sev = item.get("severity", "UNKNOWN")
                stats["severity"][sev] = stats["severity"].get(sev, 0) + 1

        return stats

    def print_summary(self):

        stats = self.get_statistics()

        print(f"\n{Fore.CYAN}{'='*60}")
        print("INTELLIGENT SCAN SUMMARY")
        print(f"{'='*60}{Style.RESET_ALL}")

        print(f"\nTotal Issues: {stats['total']}")

        for sev, count in stats["severity"].items():
            print(f"{sev:10} : {count}")

        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")