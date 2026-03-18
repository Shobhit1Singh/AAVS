import asyncio
import os
import json
import argparse
from colorama import Fore, Style

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


# ---------------------------------------
# Executor Factory
# ---------------------------------------

def create_executor(mode, base_url=None, replay_file=None) -> BaseExecutor:

    if mode == "live":
        if not base_url:
            raise ValueError("Live mode requires a base_url.")
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

    parser = ParserFactory.create_parser(swagger_path, base_url)

    # Determine target URL
    target = base_url or os.getenv("AAVS_TARGET")

    if not target and hasattr(parser, "get_base_url"):
        target = parser.get_base_url()

    if mode == "live" and not target:
        raise ValueError("No base URL found for target API.")

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

        base_payloads = attacker.generate_for_endpoint(details)

        selected_payloads = payload_strategy.generate(
            path,
            str(details.get("parameters", "")),
            base_payloads,
        )

        structured_payloads = []

        for p in selected_payloads:

            if isinstance(p, dict):
                payload = p.copy()
            else:
                payload = {"payload": str(p)}

            payload["__family__"] = payload.get("family", "generic")

            structured_payloads.append(payload)

        final_payloads = structured_payloads[:depth_limit] + auth_payloads[:10]

        for payload in final_payloads:

            try:

                result = await execution_engine.execute(endpoint, payload)

                intelligence.process(
                    endpoint,
                    payload,
                    baseline,
                    result
                )

            except Exception as e:
                print(
                    f"{Fore.RED}Execution error on {path}: {str(e)}{Style.RESET_ALL}"
                )

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

   parser = argparse.ArgumentParser(description="AAVS API Vulnerability Scanner")

   parser.add_argument(
       "--spec",
       required=True,
       help="Path to OpenAPI/Swagger specification file",
   )

   parser.add_argument(
       "--base_url",
       default="http://localhost:3000",
       help="Target API base URL",
   )

   parser.add_argument(
       "--mode",
       default="live",
       choices=["live", "mock", "replay"],
       help="Execution mode",
   )

   parser.add_argument(
       "--replay_file",
       default=None,
       help="Replay file for replay mode",
   )

   args = parser.parse_args()

   swagger_file = os.path.abspath(args.spec)

   if not os.path.exists(swagger_file):
       raise FileNotFoundError(f"Spec file not found: {swagger_file}")

   findings = run_scan(
       swagger_file,
       base_url=args.base_url,
       mode=args.mode,
       replay_file=args.replay_file,
   )

   for f in findings:
       print(json.dumps(f, indent=2))
    