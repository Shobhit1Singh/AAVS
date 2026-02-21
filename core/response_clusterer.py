import hashlib
from typing import Dict, List, Any


class ResponseClusterer:
    """
    Groups similar responses together to detect anomalies and
    avoid redundant payload testing.
    """

    def __init__(self):
        self.clusters: Dict[str, List[Dict[str, Any]]] = {}

    def _normalize_body(self, body: str) -> str:
        """
        Remove dynamic noise like IDs, timestamps, tokens.
        """
        if not body:
            return ""

        # Remove numbers (IDs, timestamps)
        body = "".join(["#" if c.isdigit() else c for c in body])

        # Trim whitespace noise
        return " ".join(body.split())

    def _generate_signature(self, response: Dict[str, Any]) -> str:
        """
        Create hash fingerprint for clustering.
        """
        body = self._normalize_body(response.get("response_body", ""))
        status = str(response.get("status_code", ""))
        length = str(len(body))

        signature_base = status + "|" + length + "|" + body[:500]

        return hashlib.md5(signature_base.encode()).hexdigest()

    def add_response(self, response: Dict[str, Any]):
        sig = self._generate_signature(response)

        if sig not in self.clusters:
            self.clusters[sig] = []

        self.clusters[sig].append(response)

    def get_anomalies(self) -> List[Dict[str, Any]]:
        """
        Returns responses that are unique or rare.
        These are HIGH VALUE for vulnerability detection.
        """
        anomalies = []

        for cluster in self.clusters.values():
            if len(cluster) <= 2:  # rare response
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
        """
        Decide if payload testing should stop early.
        If response matches large boring cluster → skip further tests.
        """
        sig = self._generate_signature(response)

        cluster = self.clusters.get(sig, [])

        # If already seen many identical responses → stop wasting time
        return len(cluster) > 5