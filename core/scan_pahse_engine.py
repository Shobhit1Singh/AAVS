class ScanPhaseEngine:

    def __init__(self, memory):
        self.memory = memory

    def determine_depth(self, endpoint):
        if self.memory.should_escalate(
            endpoint["method"],
            endpoint["path"]
        ):
            return 25
        return 10