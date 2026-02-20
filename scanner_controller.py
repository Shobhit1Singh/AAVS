from parser.api_parser import APIParser
from attacks.attack_generator import AttackGenerator
from attacks.executor import TestExecutor
from analyser.response_analyser import ResponseAnalyzer
from core.session_manager import SessionManager
from core.endpoint_discoverer import EndpointDiscoverer
from core.response_discoverer import ResponseDiscoverer
from core.waf_manager import WAFManager

import time
import os
from colorama import Fore, Style
import json


def run_scan(swagger_path, base_url=None, delay=0.1):

    parser = APIParser(swagger_path)

    target = base_url or os.getenv("AAVS_TARGET")

    if not target:
        if parser.spec.get("servers"):
            target = parser.spec["servers"][0]["url"]

    if not target:
        raise ValueError("No target base URL found.")

    parser.base_url = target
    executor_base_url = parser.base_url

    print("[*] Running endpoint discovery...")

    discoverer = EndpointDiscoverer(executor_base_url)
    discovered_paths = discoverer.run_all()

    print(f"[*] Discovered {len(discovered_paths)} extra endpoints")
    print(f"\n{Fore.CYAN}[*] Target Server: {executor_base_url}{Style.RESET_ALL}\n")

    session_manager = SessionManager(executor_base_url)

    attacker = AttackGenerator()
    executor = TestExecutor(executor_base_url, session_manager=session_manager)
    analyzer = ResponseAnalyzer()

    waf_manager = WAFManager()
    response_discoverer = ResponseDiscoverer(executor_base_url)

    dynamic_discovered = set()

    endpoints = parser.get_all_endpoints()

    for path in discovered_paths:
        endpoints.append({
            "path": path,
            "method": "GET"
        })

    all_results = []

    i = 0
    while i < len(endpoints):

        ep = endpoints[i]
        ep_path = ep["path"]
        ep_method = ep["method"].upper()

        details = parser.get_endpoint_details(ep_path, ep_method)
        payloads = attacker.generate_attacks_for_endpoint(details)

        for j, payload in enumerate(payloads, 1):

            print(f"[{j}/{len(payloads)}] {payload['attack_type']} -> {ep_method} {ep_path}", end='\r')

            headers = waf_manager.get_headers()

            result = executor.execute_attack(
                attack=payload,
                endpoint_path=ep_path,
                method=ep_method,
                extra_headers=headers
            )

            waf_detected = waf_manager.detect_waf(result)
            waf_manager.adapt(waf_detected)
            waf_manager.wait()

            response_body = result.get("response_body", "")

            new_paths = response_discoverer.extract(response_body)

            for path in new_paths:
                if path not in dynamic_discovered:
                    dynamic_discovered.add(path)
                    endpoints.append({
                        "path": path,
                        "method": "GET"
                    })

            flat_result = {
                "attack_type": payload["attack_type"],
                "severity": payload.get("severity", "UNKNOWN"),
                "param_name": payload.get("param_name", ""),
                "param_location": payload.get("param_location", ""),
                "payload": payload.get("payload", ""),
                "status_code": result.get("status_code"),
                "response_body": response_body,
                "response_headers": result.get("response_headers", {}),
                "response_time": result.get("response_time", 0),
                "success": result.get("success", True),
            }

            all_results.append(flat_result)

        i += 1

    print(f"\n{Fore.GREEN}✓ Completed all attacks across {len(endpoints)} endpoints{Style.RESET_ALL}\n")
    print(f"[*] Response-based discovery found {len(dynamic_discovered)} new endpoints")

    findings = analyzer.analyze_all_results(all_results)
    analyzer.print_summary()

    return findings


if __name__ == "__main__":

    swagger_file = "C:/AAVS/crapi-openapi-spec.json"
    target = os.getenv("AAVS_TARGET")

    findings = run_scan(swagger_file, base_url=target)

    for f in findings:
        print(json.dumps(f, indent=2))