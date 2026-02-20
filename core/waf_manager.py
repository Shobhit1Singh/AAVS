import random
import time


class WAFManager:

    WAF_SIGNATURES = [
        "cloudfront",
        "akamai",
        "incapsula",
        "sucuri",
        "waf",
        "blocked",
        "forbidden",
        "access denied"
    ]

    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        "Mozilla/5.0 (X11; Linux x86_64)",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)"
    ]

    def __init__(self):
        self.delay = 0.1
        self.blocked_count = 0

    def detect_waf(self, response):

        text = (response.get("response_body", "") + str(response.get("response_headers", ""))).lower()

        for sig in self.WAF_SIGNATURES:
            if sig in text:
                return True

        if response.get("status_code") in [401, 403, 429]:
            return True

        return False

    def adapt(self, waf_detected):

        if waf_detected:
            self.blocked_count += 1
            self.delay = min(self.delay * 2, 5)

        else:
            self.delay = max(self.delay * 0.9, 0.1)

    def get_headers(self):

        return {
            "User-Agent": random.choice(self.USER_AGENTS),
            "Accept": "*/*",
            "Connection": "keep-alive"
        }

    def wait(self):
        time.sleep(self.delay)