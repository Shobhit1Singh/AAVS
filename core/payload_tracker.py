import json
from collections import defaultdict

class PayloadTracker:
    def __init__(self):
        self.stats = defaultdict(lambda: defaultdict(lambda: {
            "attempts": 0,
            "anomalies": 0,
            "total_diff": 0.0
        }))

    def record(self, endpoint, family, diff_score, is_anomaly):
        data = self.stats[endpoint][family]
        data["attempts"] += 1
        data["total_diff"] += diff_score
        if is_anomaly:
            data["anomalies"] += 1

    def get_family_score(self, endpoint, family):
        data = self.stats[endpoint][family]
        if data["attempts"] == 0:
            return 0
        anomaly_rate = data["anomalies"] / data["attempts"]
        avg_diff = data["total_diff"] / data["attempts"]
        return anomaly_rate * 0.7 + avg_diff * 0.3

    def rank_families(self, endpoint):
        families = self.stats[endpoint]
        scored = [(f, self.get_family_score(endpoint, f)) for f in families]
        scored.sort(key=lambda x: x[1], reverse=True)
        return [f for f, _ in scored]

    def save(self, path):
        with open(path, "w") as f:
            json.dump(self.stats, f)

    def load(self, path):
        with open(path, "r") as f:
            self.stats = json.load(f)