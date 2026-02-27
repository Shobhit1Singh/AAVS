import json
from pathlib import Path
from typing import Dict, List, Any
from urllib.parse import urlparse, parse_qs
import logging

logger = logging.getLogger(__name__)


class PostmanCollectionParser:

    def __init__(self, collection_path: str):
        self.collection_path = collection_path
        self.collection = None
        self.variables = {}
        self.base_url = ""
        self.endpoints = []

        self._load_collection()
        self._extract_variables()
        self._extract_base_url()

    # --------------------------------------------------
    # LOAD COLLECTION
    # --------------------------------------------------

    def _load_collection(self):
        path = Path(self.collection_path)

        if not path.exists():
            raise FileNotFoundError(f"Collection not found: {self.collection_path}")

        with open(path, "r", encoding="utf-8") as f:
            self.collection = json.load(f)

        if "item" not in self.collection:
            raise ValueError("Invalid Postman collection format")

    # --------------------------------------------------
    # VARIABLES
    # --------------------------------------------------

    def _extract_variables(self):
        for var in self.collection.get("variable", []):
            self.variables[var.get("key")] = var.get("value", "")

    def _resolve_variables(self, text: str) -> str:
        if not isinstance(text, str):
            return text

        for key, value in self.variables.items():
            text = text.replace(f"{{{{{key}}}}}", value)

        return text

    # --------------------------------------------------
    # BASE URL
    # --------------------------------------------------

    def _extract_base_url(self):
        for key, value in self.variables.items():
            if "baseurl" in key.lower():
                self.base_url = value.rstrip("/")
                return

    # --------------------------------------------------
    # FLATTEN ITEMS (Handles Nested Folders)
    # --------------------------------------------------

    def _flatten_items(self, items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        flat = []

        for item in items:
            if "item" in item:
                flat.extend(self._flatten_items(item["item"]))
            else:
                flat.append(item)

        return flat

    # --------------------------------------------------
    # ENDPOINT EXTRACTION
    # --------------------------------------------------

    def get_all_endpoints(self) -> List[Dict[str, Any]]:
        if self.endpoints:
            return self.endpoints

        items = self._flatten_items(self.collection.get("item", []))

        for item in items:
            request = item.get("request", {})
            method = request.get("method", "GET").upper()

            raw_url = ""
            url_data = request.get("url")

            if isinstance(url_data, dict):
                raw_url = url_data.get("raw", "")
            elif isinstance(url_data, str):
                raw_url = url_data

            raw_url = self._resolve_variables(raw_url)

            parsed = urlparse(raw_url)

            headers = {
                h.get("key"): self._resolve_variables(h.get("value", ""))
                for h in request.get("header", [])
                if not h.get("disabled", False)
            }

            query_params = parse_qs(parsed.query)

            body = None
            body_data = request.get("body", {})
            mode = body_data.get("mode")

            if mode == "raw":
                body = self._resolve_variables(body_data.get("raw"))
            elif mode == "urlencoded":
                body = {
                    p.get("key"): self._resolve_variables(p.get("value"))
                    for p in body_data.get("urlencoded", [])
                    if not p.get("disabled", False)
                }
            elif mode == "formdata":
                body = {
                    p.get("key"): self._resolve_variables(p.get("value"))
                    for p in body_data.get("formdata", [])
                    if not p.get("disabled", False)
                }

            endpoint = {
                "name": item.get("name", ""),
                "path": parsed.path,
                "method": method,
                "base_url": f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
                if parsed.scheme
                else self.base_url,
                "query": query_params,
                "headers": headers,
                "body": body,
                "auth": request.get("auth", {})
            }

            self.endpoints.append(endpoint)

        logger.info(f"Discovered {len(self.endpoints)} endpoints from Postman collection")
        return self.endpoints

    # --------------------------------------------------
    # ENDPOINT DETAILS (Unified Interface)
    # --------------------------------------------------

    # def get_endpoint_details(self, path: str, method: str) -> Dict[str, Any]:
    def get_endpoint_details(self, path: str, method: str) -> Dict[str, Any]:
        method = method.upper()

        for ep in self.get_all_endpoints():
            if ep["path"] == path and ep["method"] == method:

                raw_body = ep.get("body")

                structured_body = None

            if raw_body:

                # If raw JSON string → parse it
                if isinstance(raw_body, str):
                    try:
                        parsed_json = json.loads(raw_body)
                    except Exception:
                        parsed_json = {}

                # If already dict (formdata/urlencoded)
                elif isinstance(raw_body, dict):
                    parsed_json = raw_body

                else:
                    parsed_json = {}

                structured_body = {
                    "content": {
                        "application/json": {
                            "schema": {
                                "example": parsed_json
                            }
                        }
                    }
                }

            return {
                "parameters": [],
                "request_body": structured_body,
                "responses": {},
                "security": ep.get("auth", {})
            }

            return {}

    # --------------------------------------------------
    # SECURITY SCHEMES (Unified Interface)
    # --------------------------------------------------

    def get_security_schemes(self) -> Dict[str, Dict]:
        return {}

    # --------------------------------------------------
    # API INFO (Unified Interface)
    # --------------------------------------------------

    def get_api_info(self) -> Dict[str, Any]:
        info = self.collection.get("info", {})

        return {
            "title": info.get("name", "Postman Collection"),
            "version": info.get("version", "1.0"),
            "description": info.get("description", ""),
            "base_url": self.base_url
        }