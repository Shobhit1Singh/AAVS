import random
from typing import Callable, Dict, Any, List


class IntelligentRetryEngine:
    """
    Handles smart adaptive retries ONLY when WAF filtering is suspected.
    Prevents brute retry spam.
    """

    MAX_RETRIES = 3

    def __init__(self, waf_detector: Callable[[Dict], bool]):
        self.waf_detector = waf_detector

    # ---------------------------------
    # Payload mutation strategies
    # ---------------------------------
    def _mutate_payload(self, payload: str, attempt: int) -> str:
        """
        Apply different evasion mutation per retry attempt.
        """

        if attempt == 0:
            return payload  # original

        if attempt == 1:
            # basic URL encoding
            return payload.replace(" ", "%20").replace("'", "%27")

        if attempt == 2:
            # keyword splitting
            return payload.replace("OR", "O/**/R").replace("=", " LIKE ")

        if attempt == 3:
            # case randomization
            return "".join(
                c.upper() if random.random() > 0.5 else c.lower()
                for c in payload
            )

        return payload

    # ---------------------------------
    # Smart execution wrapper
    # ---------------------------------
    async def execute_with_retry(
        self,
        executor_func: Callable,
        endpoint: Dict[str, Any],
        payload: str,
    ) -> Dict:

        last_response = None

        for attempt in range(self.MAX_RETRIES):

            mutated = self._mutate_payload(payload, attempt)

            response = await executor_func(endpoint, mutated)
            last_response = response

            # stop immediately if no WAF detected
            if not self.waf_detector(response):
                return response

        # return last response after controlled retries
        return last_response