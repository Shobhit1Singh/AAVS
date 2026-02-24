import json
from mitmproxy import http

captured_endpoints = {}

OUTPUT_FILE = "captured_endpoints.json"


def save_data():
    with open(OUTPUT_FILE, "w") as f:
        json.dump(captured_endpoints, f, indent=4)


def request(flow: http.HTTPFlow):
    req = flow.request

    path = req.path.split("?")[0]
    method = req.method

    if path not in captured_endpoints:
        captured_endpoints[path] = {
            "methods": {},
        }

    if method not in captured_endpoints[path]["methods"]:
        captured_endpoints[path]["methods"][method] = {
            "headers": dict(req.headers),
            "params": dict(req.query),
            "json": None,
        }

    if req.headers.get("content-type", "").startswith("application/json"):
        try:
            captured_endpoints[path]["methods"][method]["json"] = req.json()
        except:
            pass

    save_data()