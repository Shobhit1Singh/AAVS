import asyncio
import os
import json
import argparse
import base64
from copy import deepcopy
import re
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


# ================= JWT CORE =================

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


# ================= EXPLOIT VALIDATOR =================

class ExploitValidator:

    def __init__(self, execution_engine, base_url):
        self.exec = execution_engine
        self.base_url = base_url

    async def validate_idor(self, endpoint):
        try:
            url = endpoint["path"]
            if "1" not in url:
                return None

            ep2 = deepcopy(endpoint)
            ep3 = deepcopy(endpoint)

            ep2["path"] = url.replace("1", "2")
            ep3["path"] = url.replace("1", "3")

            r1 = await self.exec.execute(ep2, {})
            r2 = await self.exec.execute(ep3, {})

            if r1 and r2 and str(r1) != str(r2):
                return "Access to multiple user objects without authorization"

        except:
            return None

    async def validate_priv_esc(self, endpoint):
        try:
            payload = {"id": 2, "role": "admin"}

            await self.exec.execute(endpoint, payload)

            check_ep = {
                "path": "/user/2",
                "method": "GET"
            }

            res = await self.exec.execute(check_ep, {})

            if res and "admin" in str(res).lower():
                return "User role escalated to admin"

        except:
            return None

    async def validate_data_leak(self, endpoint):
        try:
            res = await self.exec.execute(endpoint, {})

            if not res:
                return None

            patterns = ["password", "ssn", "token"]

            for p in patterns:
                if re.search(p, str(res), re.IGNORECASE):
                    return f"Sensitive data exposed: {p}"

        except:
            return None

    async def validate_auth_bypass(self, endpoint, jwt_token):
        try:
            decoded = decode_jwt(jwt_token)
            if not decoded:
                return None

            tampered = tamper_role(decoded)
            forged = encode_none(tampered)

            res = await self.exec.execute(endpoint, {
                "__headers__": {"Authorization": forged}
            })

            if res and "admin" in str(res).lower():
                return "JWT role tampering successful"

            no_sig = remove_signature(jwt_token)

            res = await self.exec.execute(endpoint, {
                "__headers__": {"Authorization": no_sig}
            })

            if res:
                return "JWT accepted without signature"

        except:
            return None


# ================= EXECUTOR =================

def create_executor(mode, base_url=None, replay_file=None) -> BaseExecutor:

    if mode == "live":
        return RealHTTPExecutor(base_url, max_concurrency=20, timeout=10)

    if mode == "mock":
        return MockExecutor()

    if mode == "replay":
        with open(replay_file, "r") as f:
            recorded = json.load(f)
        return ReplayExecutor(recorded)

    raise ValueError("Invalid execution mode.")


# ================= MAIN SCAN =================

async def run_scan_async(swagger_path, base_url=None, mode="live", replay_file=None):

    parser = ParserFactory.create_parser(swagger_path, base_url)
    executor = create_executor(mode, base_url, replay_file)

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

    validator = ExploitValidator(execution_engine, base_url)

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

            result = await execution_engine.execute(endpoint, payload)
            if not result:
                continue

            if "/login" in path and isinstance(result, dict):
                jwt_token = result.get("token")

            intelligence.process(endpoint, payload, baseline, result)

        # ================= VALIDATION PHASE =================

        idor = await validator.validate_idor(endpoint)
        if idor:
            findings.append({
                "endpoint": path,
                "method": method,
                "severity": "CRITICAL",
                "reason": "IDOR",
                "evidence": idor
            })

        priv = await validator.validate_priv_esc(endpoint)
        if priv:
            findings.append({
                "endpoint": path,
                "method": method,
                "severity": "CRITICAL",
                "reason": "Privilege Escalation",
                "evidence": priv
            })

        leak = await validator.validate_data_leak(endpoint)
        if leak:
            findings.append({
                "endpoint": path,
                "method": method,
                "severity": "CRITICAL",
                "reason": "Data Leak",
                "evidence": leak
            })

        if jwt_token:
            auth = await validator.validate_auth_bypass(endpoint, jwt_token)
            if auth:
                findings.append({
                    "endpoint": path,
                    "method": method,
                    "severity": "CRITICAL",
                    "reason": "Auth Bypass",
                    "evidence": auth
                })

    print(f"\n{Fore.GREEN}✓ Completed scanning {len(ranked_endpoints)} endpoints{Style.RESET_ALL}\n")

    analyzer.print_summary()

    print("\n========== VALIDATED FINDINGS ==========")
    for f in findings:
        print(json.dumps(f, indent=2))

    severity_engine.print_ranking()

    return findings


def run_scan(swagger_path, base_url=None, mode="live", replay_file=None):
    return asyncio.run(run_scan_async(swagger_path, base_url, mode, replay_file))


# ================= CLI =================

if __name__ == "__main__":

    parser = argparse.ArgumentParser()

    parser.add_argument("--spec", required=True)
    parser.add_argument("--base_url", default="http://localhost:3000")
    parser.add_argument("--mode", default="live", choices=["live", "mock", "replay"])
    parser.add_argument("--replay_file", default=None)

    args = parser.parse_args()

    findings = run_scan(
        os.path.abspath(args.spec),
        base_url=args.base_url,
        mode=args.mode,
        replay_file=args.replay_file,
    )

    generate_html_report(findings)