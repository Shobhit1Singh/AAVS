"""
Attack Executor Module
Sends attack payloads to the API and captures responses
"""

import requests
import time
import logging
from typing import Dict, Any, Optional

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

        if session_manager:
            self.session = session_manager.get_authenticated_session()
        else:
            self.session = requests.Session()

        self.session.headers.update(self.default_headers)
        self.results = []

    def execute_attack(
        self,
        attack: Dict[str, Any],
        endpoint_path: str,
        method: str,
        extra_headers: Optional[Dict] = None,
    ) -> Dict[str, Any]:

        url = f"{self.base_url}/{endpoint_path.lstrip('/')}"
        params = {}
        headers = self.default_headers.copy()
        body = None

        if extra_headers:
            headers.update(extra_headers)

        param_location = attack.get("param_location", "body")
        param_name = attack.get("param_name", "")
        payload = attack.get("payload", "")

        if param_location == "query":
            params[param_name] = payload

        elif param_location == "header":
            headers[param_name] = str(payload)

        elif param_location == "path":
            url = url.replace(f"{{{param_name}}}", str(payload))

        elif param_location == "body":
            body = {param_name: payload}

        result = {
            "attack_type": attack.get("attack_type"),
            "severity": attack.get("severity"),
            "param_name": param_name,
            "param_location": param_location,
            "payload": str(payload)[:200],
            "url": url,
            "method": method,
            "timestamp": time.time(),
        }

        try:
            start_time = time.time()

            response = self.session.request(
                method=method,
                url=url,
                params=params,
                headers=headers,
                json=body if body else None,
                timeout=self.timeout,
                allow_redirects=False,
            )

            response_time = time.time() - start_time

            result.update(
                {
                    "status_code": response.status_code,
                    "response_time": response_time,
                    "response_headers": dict(response.headers),
                    "response_body": response.text[:5000],
                    "response_size": len(response.content),
                    "success": True,
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

        self.results.append(result)
        return result

    def execute_all_attacks(self, attacks, endpoint_path, method, delay=0.1):
        results = []
        for attack in attacks:
            results.append(self.execute_attack(attack, endpoint_path, method))
            time.sleep(delay)
        return results

    def get_results(self):
        return self.results

    def clear_results(self):
        self.results = []