import asyncio
import os
import json
from colorama import Fore, Style

from parser.api_parser import APIParser
from parser.parser_factory import ParserFactory

from attacks.attack_generator import AttackGenerator
from attacks.auth_attacks import AuthAttackGenerator
from attacks.async_executor import (
    RealHTTPExecutor,
    MockExecutor,
    ReplayExecutor,
    BaseExecutor,
)

from analyser.response_analyser import ResponseAnalyzer
from analyser.endpoints_risk_scoring_engine import EndpointRiskScorer

from core.semantic_diff_engine import SemanticDiffEngine
from core.response_clusterer import ResponseClusterer
from core.payload_strategy import PayloadStrategy
from core.scan_memory import ScanMemory
from core.execution_engine import ExecutionEngine
from core.intelligence_core import IntelligenceCore
from core.scan_pahse_engine import ScanPhaseEngine
from core.auth_Strategy_engine import AuthStrategyEngine
from core.stop_conditions_engine import StopConditionEngine


# ---------------------------------------
# Executor Factory
# ---------------------------------------

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


# ---------------------------------------
# Async Scan Engine
# ---------------------------------------

async def run_scan_async(
    swagger_path,
    base_url=None,
    mode="live",
    replay_file=None,
):

    # Correct variable usage
    parser = ParserFactory.create_parser(swagger_path, base_url)

    target = base_url or os.getenv("AAVS_TARGET")

    # Format-agnostic base URL extraction
    if not target:
        if hasattr(parser, "get_base_url"):
            target = parser.get_base_url()

    if mode == "live" and not target:
        raise ValueError("No target base URL found.")

    executor = create_executor(mode, target, replay_file)

    # Core components
    attacker = AttackGenerator()
    auth_attacker = AuthAttackGenerator()
    analyzer = ResponseAnalyzer()
    clusterer = ResponseClusterer()
    semantic_engine = SemanticDiffEngine()
    risk_scorer = EndpointRiskScorer()
    payload_strategy = PayloadStrategy()
    memory = ScanMemory()
    stop_engine = StopConditionEngine(scan_memory=memory)

    execution_engine = ExecutionEngine(executor, memory)

    intelligence = IntelligenceCore(
        semantic_engine,
        clusterer,
        analyzer,
        memory
    )

    phase_engine = ScanPhaseEngine(memory)
    auth_engine = AuthStrategyEngine(auth_attacker)

    endpoints = parser.get_all_endpoints()
    ranked_endpoints = risk_scorer.rank_endpoints(endpoints)
    auth_payloads = auth_engine.get_auth_payloads()

    # ---------------------------------------
    # Main Scan Loop
    # ---------------------------------------

    for endpoint in ranked_endpoints:

        path = endpoint["path"]
        method = endpoint["method"]

        print(f"\n{Fore.CYAN}→ Scanning {method} {path}{Style.RESET_ALL}")

        baseline = await execution_engine.get_baseline(endpoint)
        depth_limit = phase_engine.determine_depth(endpoint)

        details = parser.get_endpoint_details(path, method)

        base_payloads = attacker.generate_attacks_for_endpoint(details)

        selected_payloads = payload_strategy.generate(
            path,
            str(details.get("parameters", "unknown")),
            base_payloads,
        )

        structured_payloads = []
        for p in selected_payloads:
            p["__family__"] = p.get("family", "generic")
            structured_payloads.append(p)

        final_payloads = structured_payloads[:depth_limit] + auth_payloads[:10]

        stop_engine.reset(path)

        for payload in final_payloads:

            if stop_engine.should_stop(path):
                print(
                    f"{Fore.YELLOW}⚡ Stop condition met for {path}. Skipping remaining payloads.{Style.RESET_ALL}"
                )
                break

            result = await execution_engine.execute(endpoint, payload)

            analysis_result = intelligence.process(
                endpoint,
                payload,
                baseline,
                result
            )

            stop_engine.update(path, analysis_result)

    # ---------------------------------------
    # Post Scan Reporting
    # ---------------------------------------

    print(
        f"\n{Fore.GREEN}✓ Completed scanning {len(ranked_endpoints)} endpoints{Style.RESET_ALL}\n"
    )

    print("\nCluster Summary:")
    print(clusterer.get_cluster_summary())

    analyzer.print_summary()

    return analyzer.vulnerabilities


# ---------------------------------------
# Sync Wrapper
# ---------------------------------------

def run_scan(
    swagger_path,
    base_url=None,
    mode="live",
    replay_file=None,
):
    return asyncio.run(
        run_scan_async(
            swagger_path,
            base_url,
            mode,
            replay_file,
        )
    )


# ---------------------------------------
# Entry Point
# ---------------------------------------

if __name__ == "__main__":

    swagger_file = "C:/AAVS/postman_demo.json"
    target = os.getenv("AAVS_TARGET")

    findings = run_scan(
        swagger_file,
        base_url="http://localhost:3000",
        mode="live",
    )

    for f in findings:
        print(json.dumps(f, indent=2))