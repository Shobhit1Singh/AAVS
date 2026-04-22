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
from core.Schema_Validator import SchemaAwareValidator
from attacks.attack_generator import AttackGenerator
from attacks.async_executor import (
    RealHTTPExecutor, MockExecutor,ReplayExecutor,)
from analyser.response_analyser import ResponseAnalyzer
from analyser.endpoints_risk_scoring_engine import EndpointRiskScorer
from core.semantic_diff_engine import SemanticDiffEngine
from core.payload_strategy import PayloadStrategy
from core.scan_memory import ScanMemory
from core.execution_engine import ExecutionEngine
from core.intelligence_core import IntelligenceCore
def decode_jwt(token):
    try:
        return jwt.decode(token, options={"verify_signature": False})
    except:
        return None
def encode_none(payload):
    header = {"alg": "none", "typ": "JWT"}

    def b64(data):
        return base64.urlsafe_b64encode(
            json.dumps(data).encode()
        ).rstrip(b"=").decode()

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

def clean_base_url(base_url):
    if not base_url:
        return None

    base_url = str(base_url).strip()

    if not base_url:
        return None

    return base_url.rstrip("/")


def add_finding(
    findings,
    severity_engine,
    path,
    method,
    severity,
    reason,
    evidence
):
    issue = {
        "endpoint": path,
        "method": method,
        "severity": severity,
        "reason": reason,
        "evidence": evidence
    }

    findings.append(issue)

    severity_engine.process({
        "endpoint": path,
        "method": method,
        "vulnerabilities": [
            {
                "severity": severity,
                "type": reason}]    })

class ExploitValidator:

    def __init__(self, execution_engine):
        self.exec = execution_engine

    async def validate_idor(self, endpoint):
        try:
            path = endpoint["path"].lower()

            if "{" not in path:
                return None

            responses = []

            for val in ["1", "2", "3"]:
                res = await self.exec.execute(
                    endpoint,
                    {
                        "path_params": {
                            "id": val,
                            "user_id": val,
                            "event_id": val,
                            "booking_id": val
                        }
                    }
                )

                if res and res.get("status_code") == 200:
                    responses.append(
                        res.get("response_body", "")[:300]
                    )

            if len(set(responses)) > 1:
                return "Multiple object IDs returned different records"

        except:
            return None

    async def validate_priv_esc(self, endpoint):
        try:
            if endpoint["method"] not in ["POST", "PUT", "PATCH"]:
                return None

            res = await self.exec.execute(
                endpoint,
                {
                    "body": {
                        "role": "admin",
                        "isAdmin": True
                    }
                }
            )

            if res and res.get("status_code") in [200, 201]:
                return "Sensitive privilege fields accepted"

        except:
            return None

    async def validate_data_leak(self, endpoint):
        try:
            res = await self.exec.execute(endpoint, {})

            if not res:
                return None

            body = res.get("response_body", "").lower()

            for word in [
                "password",
                "token",
                "secret",
                "api_key",
                "authorization"
            ]:
                if word in body:
                    return f"Sensitive data exposed: {word}"

        except:
            return None

    async def validate_auth_bypass(self, endpoint, jwt_token):
        try:
            no_auth = await self.exec.execute(
                endpoint,
                {"headers": {}}
            )

            if no_auth and no_auth.get("status_code") == 200:
                return "Endpoint accessible without auth"

            decoded = decode_jwt(jwt_token)

            if not decoded:
                return None

            forged = encode_none(
                tamper_role(decoded)
            )

            forged_res = await self.exec.execute(
                endpoint,
                {
                    "headers": {
                        "Authorization": forged
                    }
                }
            )

            if forged_res and forged_res.get("status_code") == 200:
                return "Forged JWT accepted"

        except:
            return None
def create_executor(
    mode,
    base_url=None,
    replay_file=None
):
    base_url = clean_base_url(base_url)

    if mode == "live":

        if not base_url:
            raise ValueError(
                "base_url is required in live mode"
            )

        return RealHTTPExecutor(
            base_url,
            max_concurrency=20,
            timeout=10
        )

    if mode == "mock":
        return MockExecutor()

    if mode == "replay":
        with open(replay_file, "r") as f:
            recorded = json.load(f)

        return ReplayExecutor(recorded)

    raise ValueError("Invalid execution mode")
async def run_scan_async(
    swagger_path,
    base_url=None,
    mode="live",
    replay_file=None
):
    base_url = clean_base_url(base_url)

    parser = ParserFactory.create_parser(
        swagger_path,
        base_url
    )

    executor = create_executor(
        mode,
        base_url,
        replay_file
    )

    attacker = AttackGenerator()
    analyzer = ResponseAnalyzer()
    semantic_engine = SemanticDiffEngine()
    risk_scorer = EndpointRiskScorer()
    payload_strategy = PayloadStrategy()
    memory = ScanMemory()

    severity_engine = SeverityEngine()
    schema_validator = SchemaAwareValidator()

    execution_engine = ExecutionEngine(
        executor,
        memory
    )

    intelligence = IntelligenceCore(
        semantic_engine,
        analyzer,
        memory
    )

    validator = ExploitValidator(
        execution_engine
    )

    endpoints = parser.get_all_endpoints()
    ranked_endpoints = risk_scorer.rank_endpoints(
        endpoints
    )

    findings = []
    jwt_token = None

    for endpoint in ranked_endpoints:

        path = endpoint["path"]
        method = endpoint["method"]

        print(
            f"\n{Fore.CYAN}→ Scanning "
            f"{method} {path}"
            f"{Style.RESET_ALL}"
        )
        schema_findings = schema_validator.validate(
            endpoint
        )

        for sf in schema_findings:
            add_finding(
                findings,
                severity_engine,
                path,
                method,
                sf["severity"],
                sf["type"],
                "Schema analysis"
            )
        baseline = await execution_engine.get_baseline(
            endpoint
        )

        details = parser.get_endpoint_details(
            path,
            method
        )

        base_payloads = attacker.generate_for_endpoint(
            details
        )

        selected_payloads = payload_strategy.generate(
            path,
            str(details.get("parameters", "")),
            base_payloads
        )

        for payload in selected_payloads[:5]:

            result = await execution_engine.execute(
                endpoint,
                payload
            )

            if not result:
                continue

            if (
                "/login" in path.lower()
                and isinstance(result, dict)
            ):
                jwt_token = result.get("token")

            intelligence.process(
                endpoint,
                payload,
                baseline,
                result
            )
        idor = await validator.validate_idor(
            endpoint
        )

        if idor:
            add_finding(
                findings,
                severity_engine,
                path,
                method,
                "CRITICAL",
                "IDOR",
                idor
            )

        priv = await validator.validate_priv_esc(
            endpoint
        )

        if priv:
            add_finding(
                findings,
                severity_engine,
                path,
                method,
                "HIGH",
                "Privilege Escalation",
                priv
            )

        leak = await validator.validate_data_leak(
            endpoint
        )

        if leak:
            add_finding(
                findings,
                severity_engine,
                path,
                method,
                "HIGH",
                "Data Leak",
                leak
            )

        if jwt_token:

            auth = await validator.validate_auth_bypass(
                endpoint,
                jwt_token
            )

            if auth:
                add_finding(
                    findings,
                    severity_engine,
                    path,
                    method,
                    "CRITICAL",
                    "Auth Bypass",
                    auth
                )
    print(
        f"\n{Fore.GREEN}✓ Completed scanning "
        f"{len(ranked_endpoints)} endpoints"
        f"{Style.RESET_ALL}\n"
    )

    analyzer.print_summary()

    print("\n========== FINDINGS ==========")

    if findings:
        for item in findings:
            print(json.dumps(item, indent=2))
    else:
        print("No findings")

    severity_engine.print_ranking()

    return findings
def run_scan(
    swagger_path,
    base_url=None,
    mode="live",
    replay_file=None):
    return asyncio.run(
        run_scan_async(
            swagger_path,
            base_url,
            mode,
            replay_file
        )
    )
if __name__ == "__main__":

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--spec",
        required=True
    )

    parser.add_argument(
        "--base_url",
        default="http://localhost:3000"    )

    parser.add_argument(
        "--mode",
        default="live",
        choices=[
            "live",
            "mock",
            "replay"        ]    )

    parser.add_argument(
        "--replay_file",
        default=None )

    args = parser.parse_args()

    findings = run_scan(
        os.path.abspath(args.spec),
        base_url=args.base_url,
        mode=args.mode,
        replay_file=args.replay_file )

    # generate_html_report(findings)