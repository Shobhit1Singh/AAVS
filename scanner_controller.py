import asyncio
import os
import json
from colorama import Fore, Style
from core.intelligent_retry import IntelligentRetryEngine
from parser.api_parser import APIParser
from attacks.attack_generator import AttackGenerator
from attacks.executor import TestExecutor
from analyser.response_analyser import ResponseAnalyzer
from core.session_manager import SessionManager
from core.endpoint_discoverer import EndpointDiscoverer
from core.response_discoverer import ResponseDiscoverer
from core.waf_manager import WAFManager
from core.adaptive_scheduler import AdaptiveScheduler
from core.intelligence_pipeline import IntelligencePipeline


async def run_scan_async(swagger_path, base_url=None):

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
    retry_engine = IntelligentRetryEngine(waf_manager.detect_waf)
    response_discoverer = ResponseDiscoverer(executor_base_url)

    scheduler = AdaptiveScheduler(max_concurrency=20, waf_safe_concurrency=5)

    intelligence = IntelligencePipeline(waf_manager, scheduler)

    dynamic_discovered = set()
    all_results = []

    endpoints = parser.get_all_endpoints()

    for path in discovered_paths:
        endpoints.append({"path": path, "method": "GET"})

    scheduler.add_endpoints(endpoints)

    await intelligence.start()

    async def executor_func(endpoint, payload):
        loop = asyncio.get_event_loop()

        result = await loop.run_in_executor(
            None,
            lambda: executor.execute_attack(
                attack=payload,
                endpoint_path=endpoint["path"],
                method=endpoint["method"],
                extra_headers=None,
            ),
        )

        await intelligence.submit_response(result)

        return result

    def analyzer_func(response):
        flat_result = {
            "attack_type": response.get("attack_type"),
            "severity": response.get("severity", "UNKNOWN"),
            "param_name": response.get("param_name", ""),
            "param_location": response.get("param_location", ""),
            "payload": response.get("payload", ""),
            "status_code": response.get("status_code"),
            "response_body": response.get("response_body", ""),
            "response_headers": response.get("response_headers", {}),
            "response_time": response.get("response_time", 0),
            "success": response.get("success", True),
        }

        all_results.append(flat_result)

        return False

    def waf_detector_func(response):
        return False

    def attack_generator_func(endpoint, fast_mode=True):
        details = parser.get_endpoint_details(
            endpoint["path"], endpoint["method"]
        )

        payloads = attacker.generate_attacks_for_endpoint(details)

        if fast_mode:
            return payloads[:10]

        return payloads

    await scheduler.run(
        executor_func,
        analyzer_func,
        waf_detector_func,
        attack_generator_func,
        retry_engine
    )

    await intelligence.stop()

    print(
        f"\n{Fore.GREEN}✓ Completed scanning {len(endpoints)} endpoints{Style.RESET_ALL}\n"
    )

    findings = analyzer.analyze_all_results(all_results)
    analyzer.print_summary()

    return findings


def run_scan(swagger_path, base_url=None):
    return asyncio.run(run_scan_async(swagger_path, base_url))


if __name__ == "__main__":

    swagger_file = "C:/AAVS/crapi-openapi-spec.json"
    target = os.getenv("AAVS_TARGET")

    findings = run_scan(swagger_file, base_url=target)

    for f in findings:
        print(json.dumps(f, indent=2))