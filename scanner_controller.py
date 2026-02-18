from parser.api_parser import APIParser
from attacks.attack_generator import AttackGenerator
from attacks.executor import TestExecutor
from analyser.response_analyser import ResponseAnalyzer
import time
from colorama import Fore, Style
import json

def run_scan(swagger_path, base_url=None, delay=0.1):
    """
    Main scanning loop: parse API, generate attacks, execute, analyze
    """
    parser = APIParser(swagger_path)
    parser.base_url = "https://991a-2405-201-500b-1126-308b-32a5-e9ab-930a.ngrok-free.app"

    endpoints = parser.get_all_endpoints()
    
    # Use base_url from parser unless overridden
    executor_base_url = base_url or parser.base_url
    attacker = AttackGenerator()
    executor = TestExecutor(executor_base_url)
    analyzer = ResponseAnalyzer()

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

            # Flatten result for analyzer
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

    # Analyze all results
    findings = analyzer.analyze_all_results(all_results)
    analyzer.print_summary()
    return findings


if __name__ == "__main__":
    swagger_file = "C:/AAVS/vampi.yaml"  # Your Swagger/OpenAPI spec
    findings = run_scan(swagger_file)

    # Optionally print detailed findings
    for f in findings:
                        print(json.dumps(f, indent=2))
