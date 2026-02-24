import asyncio
import os
import json
import time
from colorama import Fore, Style

from parser.api_parser import APIParser
from attacks.attack_generator import AttackGenerator
from attacks.async_executor import (
    RealHTTPExecutor,
    MockExecutor,
    ReplayExecutor,
    BaseExecutor,
)
from analyser.response_analyser import ResponseAnalyzer
from core.semantic_diff_engine import SemanticDiffEngine
from core.response_clusterer import ResponseClusterer
from core.endpoint_discoverer import EndpointDiscoverer
from core.intelligent_retry import IntelligentRetryEngine
from core.waf_manager import WAFManager
from core.adaptive_scheduler import AdaptiveScheduler
from core.intelligence_pipeline import IntelligencePipeline
from analyser.endpoints_risk_scoring_engine import EndpointRiskScorer
from core.payload_strategy import PayloadStrategy


def create_executor(mode, base_url=None, replay_file=None) -> BaseExecutor:
    if mode == "live":
        return RealHTTPExecutor(base_url, max_concurrency=20, timeout=10)

    if mode == "mock":
        return MockExecutor()

    if mode == "replay":
        if not replay_file or not os.path.exists(replay_file):
            raise ValueError("Replay file not found.")
        with open(replay_file, "r") as f:
            recorded = json.load(f)
        return ReplayExecutor(recorded)

    raise ValueError("Invalid execution mode.")


async def run_scan_async(
    swagger_path,
    base_url=None,
    mode="live",
    replay_file=None,
    record_file=None,
):

    parser = APIParser(swagger_path)

    target = base_url or os.getenv("AAVS_TARGET")

    if not target and parser.spec.get("servers"):
        target = parser.spec["servers"][0]["url"]

    if mode == "live" and not target:
        raise ValueError("No target base URL found.")

    executor = create_executor(mode, target, replay_file)

    attacker = AttackGenerator()
    analyzer = ResponseAnalyzer()
    clusterer = ResponseClusterer()
    semantic_engine = SemanticDiffEngine()
    risk_scorer = EndpointRiskScorer()
    payload_strategy = PayloadStrategy()

    endpoints = parser.get_all_endpoints()
    ranked_endpoints = risk_scorer.rank_endpoints(endpoints)

    baselines = {}

    def normalize_response(result):
        if result is None:
            return None

        if isinstance(result, dict):
            return result

        normalized = {
            "status_code": getattr(result, "status", None),
            "response_body": getattr(result, "text", ""),
            "response_headers": dict(getattr(result, "headers", {})),
            "url": str(getattr(result, "url", "")),
        }

        try:
            normalized["json"] = json.loads(normalized["response_body"])
        except:
            normalized["json"] = None

        return normalized

    async def get_baseline(endpoint):

        key = f"{endpoint['method']}:{endpoint['path']}"

        if key in baselines:
            return baselines[key]

        responses = await executor.run_tests([endpoint], [{}])
        if not responses:
            return None

        baseline = normalize_response(responses[0])
        baselines[key] = baseline
        return baseline

    async def executor_func(endpoint, payload):

        baseline = await get_baseline(endpoint)
        if not baseline:
            return None

        responses = await executor.run_tests([endpoint], [payload])
        if not responses:
            return None

        result = normalize_response(responses[0])
        clusterer.add_response(result)

        diff = None
        if baseline.get("json") and result.get("json"):
            diff = semantic_engine.compare(
                baseline["json"],
                result["json"]
            )

        if diff:
            analyzer.analyze_authorization(
                baseline,
                result,
                diff,
                {"endpoint": endpoint, "payload": payload}
            )

        analyzer.analyze_result(result)

        return result

    async def run():

        for endpoint in ranked_endpoints:

            details = parser.get_endpoint_details(
                endpoint["path"],
                endpoint["method"]
            )

            base_payloads = attacker.generate_attacks_for_endpoint(details)

            selected_payloads = payload_strategy.generate(
                endpoint["path"],
                str(details.get("parameters", "unknown")),
                base_payloads,
            )

            for payload in selected_payloads[:10]:
                await executor_func(endpoint, payload)

    await run()

    print(
        f"\n{Fore.GREEN}✓ Completed scanning {len(ranked_endpoints)} endpoints{Style.RESET_ALL}\n"
    )

    print("\nCluster Summary:")
    print(clusterer.get_cluster_summary())

    analyzer.print_summary()

    return analyzer.vulnerabilities


def run_scan(
    swagger_path,
    base_url=None,
    mode="live",
    replay_file=None,
    record_file=None,
):
    return asyncio.run(
        run_scan_async(
            swagger_path,
            base_url,
            mode,
            replay_file,
            record_file,
        )
    )


if __name__ == "__main__":

    swagger_file = "C:/AAVS/crapi-openapi-spec.json"
    target = os.getenv("AAVS_TARGET")

    findings = run_scan(
        swagger_file,
        base_url=target,
        mode="mock",
        replay_file=None,
        record_file=None,
    )

    for f in findings:
        print(json.dumps(f, indent=2))