class IntelligenceCore:

    def __init__(self, semantic_engine,  analyzer, memory):
        self.semantic_engine = semantic_engine
        # self.clusterer = clusterer
        self.analyzer = analyzer
        self.memory = memory

    def process(self, endpoint, payload, baseline, result):
        if not result:
            return {"anomaly": False, "confidence": 0}

        # self.clusterer.add_response(result)

        if self.memory.has_similar_response(
            endpoint["method"],
            endpoint["path"],
            result.get("response_body", "")
        ):
            return {"anomaly": False, "confidence": 0}

        diff_score = 0

        if baseline and baseline.get("json") and result.get("json"):
            diff_score = self.semantic_engine.compare(
                baseline["json"],
                result["json"]
            ) or 0

        anomaly = diff_score > 0.2
        confidence = min(1.0, diff_score)

        self.memory.record_payload_result(
            endpoint["method"],
            endpoint["path"],
            str(payload),
            result.get("response_body", ""),
            None,
            confidence
        )

        if anomaly:
            self.memory.mark_suspicious(
                endpoint["method"],
                endpoint["path"]
            )

            self.analyzer.analyze_authorization(
                baseline,
                result,
                diff_score,
                {"endpoint": endpoint, "payload": payload}
            )

        self.analyzer.analyze_result(result)

        return {"anomaly": anomaly, "confidence": confidence}