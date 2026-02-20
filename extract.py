import json
from urllib.parse import urlparse

def extract_endpoints(collection_file, output_file="endpoints.json"):
    with open(collection_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    endpoints = []

    def walk(items):
        for item in items:
            if "item" in item:
                walk(item["item"])
            else:
                req = item["request"]
                method = req.get("method", "")
                url_data = req.get("url", {})
                raw_url = url_data.get("raw", "")
                parsed = urlparse(raw_url)

                headers = {h["key"]: h["value"] for h in req.get("header", []) if "key" in h}

                query_params = {}
                for q in url_data.get("query", []):
                    query_params[q["key"]] = q.get("value")

                body = None
                if "body" in req:
                    b = req["body"]
                    if b.get("mode") == "raw":
                        body = b.get("raw")
                    elif b.get("mode") == "urlencoded":
                        body = {p["key"]: p.get("value") for p in b.get("urlencoded", [])}

                endpoints.append({
                    "method": method,
                    "url": raw_url,
                    "path": parsed.path,
                    "headers": headers,
                    "query_params": query_params,
                    "body": body
                })

    walk(data["item"])

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(endpoints, f, indent=2)

    print(f"Extracted {len(endpoints)} endpoints to {output_file}")


if __name__ == "__main__":
    extract_endpoints("ttm.json")
