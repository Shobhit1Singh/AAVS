from parser.api_parser import APIParser
from attacks.attack_generator import AttackGenerator
from attacks.executor import TestExecutor
from analyser.response_analyser import ResponseAnalyzer
from core.session_manager import SessionManager
from core.endpoint_discoverer import EndpointDiscoverer
import time
import os
from colorama import Fore, Style
import json


def run_scan(swagger_path, base_url=None, delay=0.1):
    """
    Main scanning loop: parse API, generate attacks, execute, analyze
    """

    parser = APIParser(swagger_path)

    # -----------------------------
    # AUTO TARGET RESOLUTION
    # -----------------------------
    # Priority:
    # 1. Function argument
    # 2. Environment variable
    # 3. OpenAPI "servers" section
    # -----------------------------

    target = base_url or os.getenv("AAVS_TARGET")

    if not target:
        if parser.spec.get("servers"):
            target = parser.spec["servers"][0]["url"]

    if not target:
        raise ValueError("No target base URL found. Provide via CLI, ENV, or OpenAPI servers.")

    parser.base_url = target
    executor_base_url = parser.base_url
    print("[*] Running endpoint discovery...")

    discoverer = EndpointDiscoverer(executor_base_url)
    discovered_paths = discoverer.run_all()

    print(f"[*] Discovered {len(discovered_paths)} extra endpoints")
    print(f"\n{Fore.CYAN}[*] Target Server: {executor_base_url}{Style.RESET_ALL}\n")

    # -----------------------------
    # AUTHENTICATION SETUP
    # -----------------------------
    session_manager = SessionManager(executor_base_url)

    # Optional auth methods (unchanged)
    # session_manager.authenticate_login("/login", {"username": "admin", "password": "admin"})
    # session_manager.authenticate_bearer("YOUR_JWT_TOKEN")
    # session_manager.authenticate_api_key("YOUR_API_KEY")
    # session_manager.authenticate_basic("username", "password")

    attacker = AttackGenerator()
    executor = TestExecutor(executor_base_url, session_manager=session_manager)
    analyzer = ResponseAnalyzer()

    endpoints = parser.get_all_endpoints()
    # Add discovered endpoints as GET endpoints
    for path in discovered_paths:
        endpoints.append({
            "path": path,
            "method": "GET"
        })
    all_results = []

    for ep in endpoints:
        ep_path = ep["path"]
        ep_method = ep["method"].upper()

        details = parser.get_endpoint_details(ep_path, ep_method)
        payloads = attacker.generate_attacks_for_endpoint(details)

        for i, payload in enumerate(payloads, 1):
            print(f"[{i}/{len(payloads)}] {payload['attack_type']} -> {ep_method} {ep_path}", end='\r')

            result = executor.execute_attack(
                attack=payload,
                endpoint_path=ep_path,
                method=ep_method
            )

            flat_result = {
                "attack_type": payload["attack_type"],
                "severity": payload.get("severity", "UNKNOWN"),
                "param_name": payload.get("param_name", ""),
                "param_location": payload.get("param_location", ""),
                "payload": payload.get("payload", ""),
                "status_code": result.get("status_code"),
                "response_body": result.get("response_body", ""),
                "response_headers": result.get("response_headers", {}),
                "response_time": result.get("response_time", 0),
                "success": result.get("success", True),
            }

            all_results.append(flat_result)
            time.sleep(delay)

    print(f"\n{Fore.GREEN}✓ Completed all attacks across {len(endpoints)} endpoints{Style.RESET_ALL}\n")

    findings = analyzer.analyze_all_results(all_results)
    analyzer.print_summary()

    return findings
if __name__ == "__main__":
    swagger_file = "C:/AAVS/crapi-openapi-spec.json"

    # Optional override via ENV
    target = os.getenv("AAVS_TARGET")

    findings = run_scan(swagger_file, base_url=target)

    for f in findings:
        print(json.dumps(f, indent=2))
