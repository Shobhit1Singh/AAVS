import re
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
            r"at [A-Za-z0-9.]+\([A-Za-z0-9.]+\.java:\d+\)",
            r'File ".*", line \d+',
            r"Exception in thread",
            r"\.java:\d+\)",
        ],
        "path_disclosure": [
            r"[A-Z]:\\[\w\\]+",
            r"/var/www/",
            r"/home/[\w/]+",
            r"/usr/[\w/]+",
            r"C:\\\\",
        ],
        "database_info": [
            r"Table '[\w]+' doesn't exist",
            r"Unknown column",
            r"Undeclared variable",
        ],
        "debug_info": [
            r"DEBUG:",
            r"var_dump",
            r"print_r\(",
            r"console\.log",
        ],
    }

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

    def analyze_result(self, result: Dict[str, Any]) -> Dict[str, Any]:
        findings = []

        if not result.get("success"):
            return result

        status_code = result.get("status_code", 0)
        body = result.get("response_body", "")
        headers = result.get("response_headers", {})
        response_time = result.get("response_time", 0)

        if status_code == 500:
            findings.append({
                "type": "Server Error",
                "severity": "HIGH",
                "reason": "Payload triggered internal server error",
            })

        if body:
            for error_type, patterns in self.compiled_patterns.items():
                for pattern in patterns:
                    match = pattern.search(body)
                    if match:
                        findings.append({
                            "type": f"Information Disclosure ({error_type})",
                            "severity": "CRITICAL" if error_type == "sql_error" else "HIGH",
                            "evidence": body[max(0, match.start()-80):match.end()+80],
                        })
                        break

        if response_time > 5:
            findings.append({
                "type": "Timing Anomaly",
                "severity": "MEDIUM",
                "reason": f"Slow response ({response_time:.2f}s)",
            })

        exposed = self.DANGEROUS_HEADERS.intersection(headers.keys())
        for h in exposed:
            findings.append({
                "type": "Sensitive Header Exposure",
                "severity": "LOW",
                "reason": f"{h} header exposed",
            })

        payload = str(result.get("payload", ""))
        if status_code == 200 and "' OR '1'='1" in payload:
            findings.append({
                "type": "Possible SQL Injection",
                "severity": "CRITICAL",
            })

        rule_findings = VulnerabilityRules.run_all(result)

        if findings or rule_findings:
            result["vulnerability_detected"] = True
            result["vulnerabilities"] = findings + rule_findings
            self.vulnerabilities.append(result)
        else:
            result["vulnerability_detected"] = False

        return result

    def analyze_all_results(self, results: List[Dict]) -> List[Dict]:
        print(f"\n{Fore.CYAN}Analyzing {len(results)} results...{Style.RESET_ALL}\n")

        analyzed = [self.analyze_result(r) for r in results]

        if self.vulnerabilities:
            print(f"{Fore.RED}Found {len(self.vulnerabilities)} potential vulnerabilities{Style.RESET_ALL}\n")
        else:
            print(f"{Fore.GREEN}No vulnerabilities detected{Style.RESET_ALL}\n")

        return analyzed

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
        print("SCAN SUMMARY")
        print(f"{'='*60}{Style.RESET_ALL}")

        print(f"\nTotal Issues: {stats['total']}")

        for sev, count in stats["severity"].items():
            print(f"{sev:10} : {count}")

        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")