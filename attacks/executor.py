import requests
import time
import logging
from typing import Dict, Any, Optional, List
from requests.adapters import HTTPAdapter

logger = logging.getLogger(__name__)


class TestExecutor:
    def __init__(
        self,
        base_url: str,
        headers: Optional[Dict] = None,
        timeout: int = 10,
        session_manager=None,
    ):
        self.base_url = base_url.rstrip("/")
        self.default_headers = headers or {}
        self.timeout = timeout

        self.session = requests.Session()

        adapter = HTTPAdapter(
            pool_connections=100,
            pool_maxsize=100,
            max_retries=0,
        )

        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        if session_manager:
            auth_session = session_manager.get_authenticated_session()
            self.session.cookies.update(auth_session.cookies)
            self.session.headers.update(auth_session.headers)

        self.session.headers.update(self.default_headers)

        self.results = []

    def baseline_request(self, method, url, headers):
        try:
            res = self.session.request(
                method=method,
                url=url,
                headers=headers,
                timeout=self.timeout,
            )
            return res.text
        except:
            return ""

    def analyze_response(self, response_text: str):
        text = response_text.lower()
        vuln = False
        reason = ""

        if "<script>" in text:
            vuln = True
            reason = "Reflected XSS"

        elif "root" in text or "admin" in text:
            vuln = True
            reason = "Command Injection / Sensitive Data Leak"

        elif "sql" in text or "syntax" in text:
            vuln = True
            reason = "SQL Injection"

        return vuln, reason

    def execute_attack(
        self,
        attack: Dict[str, Any],
        endpoint_path: str,
        method: str,
        extra_headers: Optional[Dict] = None,
    ) -> List[Dict[str, Any]]:

        base_url = f"{self.base_url}/{endpoint_path.lstrip('/')}"
        headers = self.default_headers.copy()

        if extra_headers:
            headers.update(extra_headers)

        param_location = attack.get("param_location", "body")
        param_name = attack.get("param_name", "")

        payloads = attack.get("payloads", [attack.get("payload", "")])

        results = []

        for payload in payloads:

            url = base_url
            params = {}
            body = None

            if param_location == "query":
                params[param_name] = payload

            elif param_location == "header":
                headers[param_name] = str(payload)

            elif param_location == "path":
                test_values = [payload, 1, 2, 999, "admin"]
                for val in test_values:
                    test_url = url.replace(f"{{{param_name}}}", str(val))
                    results.extend(
                        self._send_request(
                            attack,
                            test_url,
                            method,
                            headers,
                            params,
                            body,
                            val,
                        )
                    )
                continue

            elif param_location == "body":
                body = attack.get("full_body")
                if not body:
                    body = {param_name: payload}

            results.extend(
                self._send_request(
                    attack,
                    url,
                    method,
                    headers,
                    params,
                    body,
                    payload,
                )
            )

        self.results.extend(results)
        return results

    def _send_request(
        self,
        attack,
        url,
        method,
        headers,
        params,
        body,
        payload,
    ):

        result = {
            "attack_type": attack.get("attack_type"),
            "severity": attack.get("severity"),
            "param_name": attack.get("param_name"),
            "param_location": attack.get("param_location"),
            "payload": str(payload)[:200],
            "url": url,
            "method": method,
            "timestamp": time.time(),
        }

        baseline = self.baseline_request(method, url, headers)

        try:
            start_time = time.time()

            response = self.session.request(
                method=method,
                url=url,
                params=params,
                headers=headers,
                json=body if body else None,
                timeout=self.timeout,
                allow_redirects=True,
            )

            response_time = time.time() - start_time

            vuln_detected, reason = self.analyze_response(response.text)

            anomaly = False
            if baseline and response.text != baseline:
                anomaly = True

            print("\n--- DEBUG ---")
            print("URL:", url)
            print("PAYLOAD:", payload)
            print("RESPONSE:", response.text[:200])
            print("VULN:", vuln_detected, reason)
            print("-------------\n")

            result.update(
                {
                    "status_code": response.status_code,
                    "response_time": response_time,
                    "response_headers": dict(response.headers),
                    "response_body": response.text[:5000],
                    "response_size": len(response.content),
                    "success": True,
                    "anomaly_detected": anomaly,
                    "vulnerability_detected": vuln_detected,
                    "vulnerability_reason": reason,
                }
            )

        except requests.exceptions.Timeout:
            result.update(
                {
                    "status_code": 0,
                    "error": "Request timeout",
                    "success": False,
                    "vulnerability_detected": True,
                    "vulnerability_reason": "Possible DoS (timeout)",
                }
            )

        except requests.exceptions.ConnectionError as e:
            result.update(
                {
                    "status_code": 0,
                    "error": str(e),
                    "success": False,
                    "vulnerability_detected": True,
                    "vulnerability_reason": "Server unreachable/crashed",
                }
            )

        except Exception as e:
            result.update(
                {
                    "status_code": 0,
                    "error": str(e),
                    "success": False,
                }
            )

        return [result]

    def execute_all_attacks(self, attacks, endpoint_path, method, delay=0, aggressive=False):
        results = []

        if aggressive:
            attacks = attacks * 3
            delay = 0

        for attack in attacks:
            results.extend(self.execute_attack(attack, endpoint_path, method))
            time.sleep(delay)

        return results

    def get_results(self):
        return self.results

    def clear_results(self):
        self.results = []