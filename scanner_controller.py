import asyncio
import os
import json
from collections import defaultdict
from colorama import Fore, Style

from parser.api_parser import APIParser
from attacks.attack_generator import AttackGenerator
from attacks.auth_attacks import AuthAttackGenerator
from attacks.async_executor import (
    RealHTTPExecutor,
    MockExecutor,
    ReplayExecutor,
    BaseExecutor,
)
from analyser.response_analyser import ResponseAnalyzer
from core.semantic_diff_engine import SemanticDiffEngine
from core.response_clusterer import ResponseClusterer
from analyser.endpoints_risk_scoring_engine import EndpointRiskScorer
from core.payload_strategy import PayloadStrategy


class PayloadPerformanceTracker:
    def __init__(self):
        self.stats = defaultdict(lambda: defaultdict(lambda: {
            "attempts": 0,
            "anomalies": 0,
            "total_diff": 0.0
        }))

    def record(self, endpoint, family, diff_score, is_anomaly):
        data = self.stats[endpoint][family]
        data["attempts"] += 1
        data["total_diff"] += diff_score or 0
        if is_anomaly:
            data["anomalies"] += 1

    def family_score(self, endpoint, family):
        data = self.stats[endpoint][family]
        if data["attempts"] == 0:
            return 0
        anomaly_rate = data["anomalies"] / data["attempts"]
        avg_diff = data["total_diff"] / data["attempts"]
        return (anomaly_rate * 0.7) + (avg_diff * 0.3)

    def rank_families(self, endpoint):
        families = self.stats[endpoint]
        scored = [(f, self.family_score(endpoint, f)) for f in families]
        scored.sort(key=lambda x: x[1], reverse=True)
        return [f for f, _ in scored]


class EscalationEngine:
    def __init__(self):
        self.stage2 = 0.3
        self.stage3 = 0.6

    def stage(self, score):
        if score >= self.stage3:
            return 3
        if score >= self.stage2:
            return 2
        return 1


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
    auth_attacker = AuthAttackGenerator()
    analyzer = ResponseAnalyzer()
    clusterer = ResponseClusterer()
    semantic_engine = SemanticDiffEngine()
    risk_scorer = EndpointRiskScorer()
    payload_strategy = PayloadStrategy()

    tracker = PayloadPerformanceTracker()
    escalator = EscalationEngine()

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

    async def execute_payload(endpoint, payload, family):

        baseline = await get_baseline(endpoint)
        if not baseline:
            return

        responses = await executor.run_tests([endpoint], [payload])
        if not responses:
            return

        result = normalize_response(responses[0])
        clusterer.add_response(result)

        diff_score = 0
        if baseline.get("json") and result.get("json"):
            diff_score = semantic_engine.compare(
                baseline["json"],
                result["json"]
            ) or 0

        is_anomaly = diff_score > 0.2

        tracker.record(endpoint["path"], family, diff_score, is_anomaly)

        if is_anomaly:
            analyzer.analyze_authorization(
                baseline,
                result,
                diff_score,
                {"endpoint": endpoint, "payload": payload}
            )

        analyzer.analyze_result(result)

    async def run():

        jwt_attacks = auth_attacker.generate_jwt_attacks()
        api_key_attacks = auth_attacker.generate_api_key_attacks()

        auth_payloads = []

        for attack in jwt_attacks:
            for token in attack.get("payloads", []):
                if token:
                    auth_payloads.append({
                        "headers": {"Authorization": f"Bearer {token}"},
                        "__family__": "auth_jwt"
                    })

        for attack in api_key_attacks:
            for key in attack.get("payloads", []):
                auth_payloads.append({
                    "headers": {"X-API-Key": key},
                    "__family__": "auth_apikey"
                })

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

            structured_payloads = []
            for p in selected_payloads:
                family = p.get("family", "generic")
                p["__family__"] = family
                structured_payloads.append(p)

            final_payloads = structured_payloads[:15] + auth_payloads[:10]

            ranked_families = tracker.rank_families(endpoint["path"])

            if ranked_families:
                final_payloads.sort(
                    key=lambda x: tracker.family_score(
                        endpoint["path"],
                        x.get("__family__", "generic")
                    ),
                    reverse=True
                )

            for payload in final_payloads:

                family = payload.get("__family__", "generic")
                score = tracker.family_score(endpoint["path"], family)
                stage = escalator.stage(score)

                if stage == 1:
                    await execute_payload(endpoint, payload, family)

                elif stage == 2:
                    await execute_payload(endpoint, payload, family)

                elif stage == 3:
                    await execute_payload(endpoint, payload, family)
                    await execute_payload(endpoint, payload, family)

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

    swagger_file = "C:/AAVS/smart_booking_ai.yaml"
    target = os.getenv("AAVS_TARGET")

    findings = run_scan(
        swagger_file,
        base_url=target,
        mode="live",
    )

    for f in findings:
        print(json.dumps(f, indent=2))