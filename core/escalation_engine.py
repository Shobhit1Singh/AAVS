class EscalationEngine:
    def __init__(self):
        self.threshold_stage2 = 0.3
        self.threshold_stage3 = 0.6

    def decide_stage(self, anomaly_score):
        if anomaly_score >= self.threshold_stage3:
            return 3
        if anomaly_score >= self.threshold_stage2:
            return 2
        return 1