import math
from typing import Dict, Any


class ThreatModelEngine:

    def __init__(self, memory):
        self.memory = memory

    def _get_endpoint(self, method: str, path: str) -> Dict[str, Any]:
        key = f"{method.upper()}::{path}"
        return self.memory.memory["endpoints"].get(key, {})

    def _get_payloads(self, method: str, path: str):
        key = f"{method.upper()}::{path}"
        return self.memory.memory["payload_history"].get(key, [])

    def _get_vulns(self, method: str, path: str):
        key = f"{method.upper()}::{path}"
        return self.memory.memory["vulnerabilities"].get(key, [])

    def compute_anomaly_score(self, method: str, path: str) -> float:
        payloads = self._get_payloads(method, path)
        if not payloads:
            return 0.0

        confidence_values = [p["confidence"] for p in payloads]
        avg_conf = sum(confidence_values) / len(confidence_values)
        variance = sum((c - avg_conf) ** 2 for c in confidence_values) / len(confidence_values)

        return round(avg_conf + math.sqrt(variance), 4)

    def compute_cluster_instability(self, method: str, path: str) -> float:
        payloads = self._get_payloads(method, path)
        if not payloads:
            return 0.0

        cluster_counts = {}
        for p in payloads:
            cid = p.get("cluster_id")
            if not cid:
                continue
            cluster_counts[cid] = cluster_counts.get(cid, 0) + 1

        total = sum(cluster_counts.values())
        if total == 0:
            return 0.0

        entropy = 0.0
        for count in cluster_counts.values():
            prob = count / total
            entropy -= prob * math.log(prob, 2)

        return round(entropy, 4)

    def compute_defensive_pressure(self, method: str, path: str) -> float:
        payloads = self._get_payloads(method, path)
        if not payloads:
            return 0.0

        repetitive_hits = 0
        response_hashes = set()

        for p in payloads:
            h = p["response_hash"]
            if h in response_hashes:
                repetitive_hits += 1
            response_hashes.add(h)

        ratio = repetitive_hits / len(payloads)
        return round(ratio, 4)

    def compute_risk_score(self, method: str, path: str) -> float:
        anomaly = self.compute_anomaly_score(method, path)
        instability = self.compute_cluster_instability(method, path)
        vuln_count = len(self._get_vulns(method, path))

        risk = anomaly * 0.5 + instability * 0.3 + vuln_count * 0.2
        return round(risk, 4)

    def get_attack_mode(self, method: str, path: str) -> str:
        anomaly = self.compute_anomaly_score(method, path)
        instability = self.compute_cluster_instability(method, path)
        pressure = self.compute_defensive_pressure(method, path)
        vuln_count = len(self._get_vulns(method, path))

        if pressure > 0.6:
            return "stealth"

        if vuln_count > 2 and anomaly > 0.7:
            return "aggressive"

        if instability > 1.0:
            return "deep_logic"

        return "baseline"

    def get_endpoint_summary(self, method: str, path: str) -> Dict[str, Any]:
        return {
            "anomaly_score": self.compute_anomaly_score(method, path),
            "cluster_instability": self.compute_cluster_instability(method, path),
            "defensive_pressure": self.compute_defensive_pressure(method, path),
            "risk_score": self.compute_risk_score(method, path),
            "recommended_mode": self.get_attack_mode(method, path)
        }