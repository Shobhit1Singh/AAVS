import json
from urllib.parse import urlparse, parse_qs


def extract_requests(items, requests):
    for item in items:
        if "item" in item:
            extract_requests(item["item"], requests)
        elif "request" in item:
            requests.append(item["request"])


def get_variables(collection):
    vars = {}
    for v in collection.get("variable", []):
        vars[v["key"]] = v.get("value", "")
    return vars


def resolve_vars(text, variables):
    if not isinstance(text, str):
        return text
    for k, v in variables.items():
        text = text.replace("{{" + k + "}}", v)
    return text


def build_schema_from_json(data):
    if isinstance(data, dict):
        return {
            "type": "object",
            "properties": {k: build_schema_from_json(v) for k, v in data.items()}
        }
    if isinstance(data, list):
        if data:
            return {"type": "array", "items": build_schema_from_json(data[0])}
        return {"type": "array", "items": {}}
    if isinstance(data, int):
        return {"type": "integer"}
    if isinstance(data, float):
        return {"type": "number"}
    if isinstance(data, bool):
        return {"type": "boolean"}
    return {"type": "string"}


def convert_postman_to_openapi(collection):
    requests = []
    extract_requests(collection["item"], requests)

    variables = get_variables(collection)

    openapi = {
        "openapi": "3.0.0",
        "info": {"title": collection["info"]["name"], "version": "1.0.0"},
        "servers": [],
        "paths": {}
    }

    base_url_set = False

    for req in requests:
        method = req.get("method", "get").lower()
        url_field = req.get("url")

        if isinstance(url_field, str):
            raw_url = url_field

        elif isinstance(url_field, dict):
            if "raw" in url_field:
                raw_url = url_field["raw"]
            else:
                host = ".".join(url_field.get("host", []))
                path = "/" + "/".join(url_field.get("path", []))
                raw_url = "http://" + host + path
        else:
            continue

        raw_url = resolve_vars(raw_url, variables)

        parsed = urlparse(raw_url)

        if not parsed.netloc:
            continue

        if not base_url_set:
            base = f"{parsed.scheme}://{parsed.netloc}"
            openapi["servers"].append({"url": base})
            base_url_set = True

        path = parsed.path or "/"

        if path not in openapi["paths"]:
            openapi["paths"][path] = {}

        operation = {"responses": {"200": {"description": "Success"}}}

        params = []

        query_params = parse_qs(parsed.query)
        for name in query_params:
            params.append({
                "name": name,
                "in": "query",
                "schema": {"type": "string"}
            })

        for h in req.get("header", []):
            params.append({
                "name": h.get("key", ""),
                "in": "header",
                "schema": {"type": "string"}
            })

        if params:
            operation["parameters"] = params

        body = req.get("body")
        if body and body.get("mode") == "raw":
            raw = resolve_vars(body.get("raw", "").strip(), variables)
            try:
                body_json = json.loads(raw)
                operation["requestBody"] = {
                    "content": {
                        "application/json": {
                            "schema": build_schema_from_json(body_json)
                        }
                    }
                }
            except:
                operation["requestBody"] = {
                    "content": {
                        "text/plain": {
                            "schema": {"type": "string"}
                        }
                    }
                }

        openapi["paths"][path][method] = operation

    return openapi


if __name__ == "__main__":
    with open("ttm.json") as f:
        collection = json.load(f)

    spec = convert_postman_to_openapi(collection)

    with open("openapi.json", "w") as f:
        json.dump(spec, f, indent=2)