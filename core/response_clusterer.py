import hashlib
import re
import json
from typing import Dict, List, Any


class ResponseClusterer:
    def __init__(self):
        self.clusters: Dict[str, List[Dict[str, Any]]] = {}

    def _normalize_body(self, body: str) -> str:
        if not body:
            return ""

        # Replace only long numeric sequences (timestamps, IDs)
        body = re.sub(r'\d{4,}', '####', body)

        # Normalize whitespace
        body = " ".join(body.split())

        return body

    def _extract_structure(self, body: str) -> str:
        try:
            parsed = json.loads(body)

            if isinstance(parsed, dict):
                return "|".join(sorted(parsed.keys()))

            elif isinstance(parsed, list) and len(parsed) > 0:
                if isinstance(parsed[0], dict):
                    return "list|" + "|".join(sorted(parsed[0].keys()))

            return "generic"

        except:
            return "non_json"

    def _generate_signature(self, response: Dict[str, Any]) -> str:
        raw_body = response.get("response_body", "")
        body = self._normalize_body(raw_body)

        status = str(response.get("status_code", ""))
        structure = self._extract_structure(body)

        # Use full body hash instead of truncation
        body_hash = hashlib.md5(body.encode()).hexdigest()

        signature_base = f"{status}|{structure}|{body_hash}"

        return hashlib.md5(signature_base.encode()).hexdigest()

    def add_response(self, response: Dict[str, Any]):
        sig = self._generate_signature(response)

        if sig not in self.clusters:
            self.clusters[sig] = []

        self.clusters[sig].append(response)

    def get_anomalies(self) -> List[Dict[str, Any]]:
        anomalies = []

        for cluster in self.clusters.values():
            if len(cluster) <= 2:
                anomalies.extend(cluster)

        return anomalies

    def get_cluster_summary(self) -> Dict[str, Any]:
        summary = {
            "total_clusters": len(self.clusters),
            "largest_cluster_size": 0,
            "total_responses": 0
        }

        for cluster in self.clusters.values():
            size = len(cluster)
            summary["total_responses"] += size
            summary["largest_cluster_size"] = max(
                summary["largest_cluster_size"], size
            )

        return summary

    def should_skip_payload(self, response: Dict[str, Any]) -> bool:
        sig = self._generate_signature(response)
        cluster = self.clusters.get(sig, [])

        return len(cluster) > 5