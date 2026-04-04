class IntelligenceCore:

    def __init__(self, semantic_engine, analyzer, memory):
        self.semantic_engine = semantic_engine
        self.analyzer = analyzer
        self.memory = memory

    def process(self, endpoint, payload, baseline, result):

        if not result:
            return {"anomaly": False, "confidence": 0}

        method = endpoint.get("method", "GET")
        path = endpoint.get("path", "")

        body = result.get("response_body", "")

        # ----------------------------
        # MEMORY DEDUP (FIXED)
        # ----------------------------
        if self.memory.has_similar_response(method, path, body):
            return {"anomaly": False, "confidence": 0}

        # ----------------------------
        # SEMANTIC DIFF (SAFE)
        # ----------------------------
        diff_score = 0

        if baseline and baseline.get("json") and result.get("json"):
            try:
                diff_score = self.semantic_engine.compare(
                    baseline["json"],
                    result["json"]
                ) or 0
            except Exception:
                diff_score = 0

        anomaly = diff_score > 0.2
        confidence = min(1.0, diff_score)

        # ----------------------------
        # STORE RESULT (FIXED STRUCTURE)
        # ----------------------------
        self.memory.record_payload_result(
            method,
            path,
            str(payload),
            body,
            result.get("status_code"),
            confidence
        )

        # ----------------------------
        # AUTH ANALYSIS (SAFE GUARDS)
        # ----------------------------
        if anomaly and baseline:
            self.memory.mark_suspicious(method, path)

            try:
                self.analyzer.analyze_authorization(
                    baseline,
                    result,
                    {"diff_score": diff_score},
                    {"endpoint": endpoint, "payload": payload}
                )
            except Exception:
                pass

        # ----------------------------
        # ALWAYS RUN ANALYZER
        # ----------------------------
        try:
            self.analyzer.analyze_result(result)
        except Exception:
            pass

        return {
            "anomaly": anomaly,
            "confidence": confidence
        }