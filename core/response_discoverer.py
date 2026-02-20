import re
from urllib.parse import urlparse

class ResponseDiscoverer:
    def __init__(self, base_url):
        parsed = urlparse(base_url)
        self.base_domain = parsed.netloc

        self.api_patterns = [
            r'["\'](/api/[^"\']+)["\']',
            r'["\'](/v\d+/[^"\']+)["\']',
            r'["\'](/auth/[^"\']+)["\']',
            r'["\'](/admin/[^"\']+)["\']',
            r'["\'](https?://[^"\']+)["\']',
        ]

    def extract(self, response_text):
        discovered = set()

        for pattern in self.api_patterns:
            matches = re.findall(pattern, response_text)

            for m in matches:
                if m.startswith("http"):
                    if self.base_domain in m:
                        path = urlparse(m).path
                        discovered.add(path)
                else:
                    discovered.add(m)

        return list(discovered)