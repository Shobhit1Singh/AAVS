import random
import hashlib


class PayloadStrategy:
    def __init__(self):
        self.history = {}
        self.anomaly_scores = {}
        self.confirmed = set()

    def generate(self, endpoint, param, base_payloads):
        key = self._key(endpoint, param)

        if key in self.confirmed:
            return []

        if key not in self.history:
            self.history[key] = []

        scored = self._prioritize(base_payloads, key)
        return scored

    def feedback(self, endpoint, param, payload, response):
        key = self._key(endpoint, param)

        score = self._analyze(response)
        self.history.setdefault(key, []).append((payload, score))

        if score > 0.8:
            self.confirmed.add(key)

        self.anomaly_scores[key] = max(
            score,
            self.anomaly_scores.get(key, 0)
        )

    def should_continue(self, endpoint, param):
        key = self._key(endpoint, param)

        if key in self.confirmed:
            return False

        if self.anomaly_scores.get(key, 0) > 0.9:
            return False

        return True

    def _prioritize(self, payloads, key):
        random.shuffle(payloads)

        if self.anomaly_scores.get(key, 0) > 0.5:
            return payloads[:5]

        return payloads

    def _analyze(self, response):
        score = 0

        status = getattr(response, "status_code", 0)
        body = getattr(response, "text", "")

        if status >= 500:
            score += 0.6

        if "error" in body.lower():
            score += 0.3

        if len(body) > 10000:
            score += 0.2

        return min(score, 1.0)

    def _key(self, endpoint, param):
        raw = f"{endpoint}:{param}"
        return hashlib.md5(raw.encode()).hexdigest()