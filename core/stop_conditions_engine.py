class StopConditionEngine:

    def __init__(
        self,
        scan_memory=None,
        max_attempts=40,
        repeat_response_limit=5,
        confidence_stability_window=6,
        anomaly_plateau_window=8,
        reproduction_threshold=3,
        stability_delta=0.02,
    ):
        self.scan_memory = scan_memory

        self.max_attempts = max_attempts
        self.repeat_response_limit = repeat_response_limit
        self.confidence_stability_window = confidence_stability_window
        self.anomaly_plateau_window = anomaly_plateau_window
        self.reproduction_threshold = reproduction_threshold
        self.stability_delta = stability_delta

        self.state = {}

    def _get_state(self, endpoint_key):
        if endpoint_key not in self.state:
            self.state[endpoint_key] = {
                "attempts": 0,
                "last_response_hash": None,
                "repeat_count": 0,
                "confidence_history": [],
                "anomaly_history": [],
                "reproduction_hits": 0,
            }
        return self.state[endpoint_key]

    def reset(self, endpoint_key):
        if endpoint_key in self.state:
            del self.state[endpoint_key]

    def record(
        self,
        endpoint_key,
        response_hash,
        confidence,
        anomaly,
        vulnerability_confirmed=False,
    ):
        s = self._get_state(endpoint_key)

        s["attempts"] += 1

        if response_hash == s["last_response_hash"]:
            s["repeat_count"] += 1
        else:
            s["repeat_count"] = 0

        s["last_response_hash"] = response_hash

        s["confidence_history"].append(confidence)
        s["anomaly_history"].append(1 if anomaly else 0)

        if vulnerability_confirmed:
            s["reproduction_hits"] += 1

    def should_stop(self, endpoint_key):
        s = self._get_state(endpoint_key)

        if s["attempts"] >= self.max_attempts:
            return True, "max_attempts"

        if s["repeat_count"] >= self.repeat_response_limit:
            return True, "repeat_response"

        if s["reproduction_hits"] >= self.reproduction_threshold:
            return True, "vulnerability_confirmed"

        if self._confidence_stable(s):
            return True, "confidence_stable"

        if self._anomaly_plateau(s):
            return True, "anomaly_plateau"

        return False, None

    def _confidence_stable(self, s):
        history = s["confidence_history"]

        if len(history) < self.confidence_stability_window:
            return False

        window = history[-self.confidence_stability_window:]
        max_c = max(window)
        min_c = min(window)

        return (max_c - min_c) < self.stability_delta

    def _anomaly_plateau(self, s):
        history = s["anomaly_history"]

        if len(history) < self.anomaly_plateau_window:
            return False

        window = history[-self.anomaly_plateau_window:]

        return sum(window) == 0