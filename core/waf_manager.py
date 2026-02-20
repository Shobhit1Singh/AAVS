import random


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
        self.total_requests = 0
        self.waf_hits = 0

    def detect_waf(self, response):
        self.total_requests += 1

        text = (
            response.get("response_body", "") +
            str(response.get("response_headers", ""))
        ).lower()

        for sig in self.WAF_SIGNATURES:
            if sig in text:
                self.waf_hits += 1
                return True

        if response.get("status_code") in [401, 403, 429]:
            self.waf_hits += 1
            return True

        return False

    def get_headers(self):
        return {
            "User-Agent": random.choice(self.USER_AGENTS),
            "Accept": "*/*",
            "Connection": "keep-alive"
        }

    def get_stats(self):
        return {
            "total_requests": self.total_requests,
            "waf_hits": self.waf_hits
        }