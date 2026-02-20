import requests
import re

COMMON_API_PATHS = [
    "/api",
    "/api/v1",
    "/v1",
    "/auth",
    "/admin",
    "/graphql",
    "/users",
    "/login",
    "/signup",
    "/products",
]

class EndpointDiscoverer:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()

    def discover_common_paths(self):
        discovered = []

        for path in COMMON_API_PATHS:
            url = self.base_url + path
            try:
                r = self.session.get(url, timeout=5)
                if r.status_code < 400:
                    discovered.append(path)
            except:
                pass

        return discovered

    def discover_from_robots(self):
        discovered = []
        try:
            r = self.session.get(self.base_url + "/robots.txt", timeout=5)
            lines = r.text.splitlines()

            for line in lines:
                if "Disallow:" in line:
                    path = line.split(":")[1].strip()
                    if path.startswith("/"):
                        discovered.append(path)
        except:
            pass

        return discovered

    def discover_from_js(self):
        discovered = []

        try:
            r = self.session.get(self.base_url, timeout=5)
            js_files = re.findall(r'src="(.*?\.js)"', r.text)

            for js in js_files:
                if not js.startswith("http"):
                    js = self.base_url + js

                js_r = self.session.get(js, timeout=5)

                endpoints = re.findall(r'["\'](/api/[^"\']+)["\']', js_r.text)
                discovered.extend(endpoints)

        except:
            pass

        return list(set(discovered))

    def run_all(self):
        results = set()

        results.update(self.discover_common_paths())
        results.update(self.discover_from_robots())
        results.update(self.discover_from_js())

        return list(results)