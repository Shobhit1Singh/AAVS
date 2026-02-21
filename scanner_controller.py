"""
Async AAVS Runner with Endpoint Risk Scoring Engine
"""

import asyncio
import os
import json
from colorama import Fore, Style
from parser.api_parser import APIParser
from attacks.attack_generator import AttackGenerator
from attacks.async_executor import AsyncTestExecutor
from analyser.response_analyser import ResponseAnalyzer
from core.session_manager import SessionManager
from core.endpoint_discoverer import EndpointDiscoverer
from core.response_discoverer import ResponseDiscoverer
from core.intelligent_retry import IntelligentRetryEngine
from core.waf_manager import WAFManager
from core.adaptive_scheduler import AdaptiveScheduler
from core.intelligence_pipeline import IntelligencePipeline
import aiohttp
from analyser.endpoints_risk_scoring_engine import EndpointRiskScorer


async def run_scan_async(swagger_path, base_url=None):
    parser = APIParser(swagger_path)
    target = base_url or os.getenv("AAVS_TARGET")
    if not target and parser.spec.get("servers"):
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
    executor = AsyncTestExecutor(executor_base_url, max_concurrency=20, timeout=10)
    analyzer = ResponseAnalyzer()
    waf_manager = WAFManager()
    risk_scorer = EndpointRiskScorer()
    retry_engine = IntelligentRetryEngine(waf_manager.detect_waf)
    scheduler = AdaptiveScheduler(max_concurrency=20, waf_safe_concurrency=5)
    intelligence = IntelligencePipeline(waf_manager, scheduler)

    endpoints = parser.get_all_endpoints()
    for path in discovered_paths:
        endpoints.append({"path": path, "method": "GET"})

    # ----------------------------
    # Apply risk scoring and rank endpoints
    # ----------------------------
    ranked_endpoints = risk_scorer.rank_endpoints(endpoints)
    scheduler.add_endpoints(ranked_endpoints)
    await intelligence.start()

    all_results = []

    # ----------------------------
    # Executor wrapper with live session
    # ----------------------------
    async def executor_func(session, endpoint, payload):
        result = await executor.send_request(session, endpoint, payload)
        await intelligence.submit_response(result)
        all_results.append({
            "attack_type": result.get("attack_type"),
            "severity": result.get("severity", "UNKNOWN"),
            "param_name": result.get("param_name", ""),
            "param_location": result.get("param_location", ""),
            "payload": result.get("payload", ""),
            "status_code": result.get("status_code"),
            "response_body": result.get("response_body", ""),
            "response_headers": result.get("response_headers", {}),
            "response_time": result.get("response_time", 0),
            "success": result.get("success", True),
            "reason": result.get("reason", "")
        })
        return result

    # ----------------------------
    # WAF detector
    # ----------------------------
    def waf_detector_func(response):
        return waf_manager.detect_waf(response)

    # ----------------------------
    # Attack generator wrapper
    # ----------------------------
    def attack_generator_func(endpoint, fast_mode=True):
        details = parser.get_endpoint_details(endpoint["path"], endpoint["method"])
        payloads = attacker.generate_attacks_for_endpoint(details)
        # Limit payloads for fast mode or prioritize risk
        return payloads[:10] if fast_mode else payloads

    # ----------------------------
    # Run scheduler with retries using live session
    # ----------------------------
    async with aiohttp.ClientSession() as session:
        await scheduler.run(
            lambda ep, pl: executor_func(session, ep, pl),
            lambda r: False,  # analysis handled inside executor_func
            waf_detector_func,
            attack_generator_func,
            retry_engine
        )

    await intelligence.stop()

    print(f"\n{Fore.GREEN}✓ Completed scanning {len(ranked_endpoints)} endpoints{Style.RESET_ALL}\n")
    findings = analyzer.analyze_all_results(all_results)
    analyzer.print_summary()
    return findings


def run_scan(swagger_path, base_url=None):
    return asyncio.run(run_scan_async(swagger_path, base_url))


if __name__ == "__main__":
    swagger_file = "C:/AAVS/crapi-openapi-spec.json"
    target = os.getenv("AAVS_TARGETS")
    findings = run_scan(swagger_file, base_url=target)

    for f in findings:
        print(json.dumps(f, indent=2))