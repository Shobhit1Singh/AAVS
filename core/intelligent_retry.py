import random
from typing import Callable, Dict, Any, Union


class IntelligentRetryEngine:
    """
    Handles smart adaptive retries ONLY when WAF filtering is suspected.
    Prevents brute retry spam.
    Supports BOTH string and JSON payloads.
    """

    MAX_RETRIES = 3

    def __init__(self, waf_detector: Callable[[Dict], bool]):
        self.waf_detector = waf_detector

    # ---------------------------------
    # Internal helpers
    # ---------------------------------

    def _mutate_string(self, text: str, attempt: int) -> str:
        """Apply mutation strategies to a single string value."""

        if attempt == 0:
            return text

        if attempt == 1:
            return text.replace(" ", "%20").replace("'", "%27")

        if attempt == 2:
            return text.replace("OR", "O/**/R").replace("=", " LIKE ")

        if attempt == 3:
            return "".join(
                c.upper() if random.random() > 0.5 else c.lower()
                for c in text
            )

        return text

    def _mutate_payload(
        self,
        payload: Union[str, Dict[str, Any]],
        attempt: int
    ) -> Union[str, Dict[str, Any]]:
        """
        Mutate payload safely whether it is:
        - raw string
        - JSON dictionary
        """

        # STRING payload (query params, form bodies etc)
        if isinstance(payload, str):
            return self._mutate_string(payload, attempt)

        # DICT payload (JSON bodies)
        if isinstance(payload, dict):
            mutated = {}

            for key, value in payload.items():

                if isinstance(value, str):
                    mutated[key] = self._mutate_string(value, attempt)
                else:
                    mutated[key] = value

            return mutated

        return payload

    # ---------------------------------
    # Smart execution wrapper
    # ---------------------------------

    async def execute_with_retry(
        self,
        executor_func: Callable,
        endpoint: Dict[str, Any],
        payload: Union[str, Dict[str, Any]],
    ) -> Dict:

        last_response = None

        for attempt in range(self.MAX_RETRIES):

            mutated = self._mutate_payload(payload, attempt)

            response = await executor_func(endpoint, mutated)
            last_response = response

            # Stop immediately if no WAF detected
            if not self.waf_detector(response):
                return response

        return last_response