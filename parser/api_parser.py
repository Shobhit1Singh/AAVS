import os
import prance
import json
import requests
from pathlib import Path
from typing import Dict, List, Optional, Any
import logging
from colorama import Fore, Style, init

init(autoreset=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class APIParser:

    COMMON_SPEC_PATHS = [
        "/openapi.json",
        "/swagger.json",
        "/v3/api-docs",
        "/api-docs",
        "/docs/openapi.json"
    ]

    def __init__(self, spec_path: str, base_url: Optional[str] = None):
        self.spec_source = spec_path
        self.spec = None
        self.base_url = None
        self.cli_base_url = base_url
        self.endpoints = []

        if spec_path.startswith("http"):
            self._load_remote_spec()
        else:
            self._load_local_spec()

        self._extract_base_info()
        logger.info(f"{Fore.GREEN}Loaded API specification")

    # ---------------- LOAD ----------------

    def _load_local_spec(self):
        path = Path(self.spec_source)

        if not path.exists():
            raise FileNotFoundError(f"Spec file not found: {self.spec_source}")

        parser = prance.ResolvingParser(str(path))
        self.spec = parser.specification

    def _load_remote_spec(self):
        base = self.spec_source.rstrip("/")

        for path in self.COMMON_SPEC_PATHS:
            url = base + path
            try:
                r = requests.get(url, timeout=5)
                if r.status_code == 200:
                    self.spec = r.json()
                    logger.info(f"{Fore.GREEN}Found spec at: {url}")
                    return
            except:
                continue

        raise ValueError("No OpenAPI spec found")

    # ---------------- BASE ----------------

    def _extract_base_info(self):
        info = self.spec.get('info', {})

        self.api_title = info.get('title', 'Unknown API')
        self.api_version = info.get('version', '1.0.0')

        self.base_url = self._resolve_base_url()

    def _resolve_base_url(self) -> str:
        if self.cli_base_url:
            return self.cli_base_url.rstrip("/")

        servers = self.spec.get("servers", [])
        if servers:
            return servers[0]["url"].rstrip("/")

        return self.spec_source.rstrip("/")

    # ---------------- ENDPOINTS ----------------

    def get_all_endpoints(self) -> List[Dict[str, Any]]:
        endpoints = []
        paths = self.spec.get('paths', {})

        for path, methods in paths.items():
            for method, details in methods.items():
                if method.lower() in ["get", "post", "put", "delete", "patch"]:

                    params = self._extract_params(details)

                    endpoints.append({
                        "path": path,
                        "method": method.upper(),
                        "params": params,
                        "raw_parameters": details.get("parameters", []),
                        "request_body": details.get("requestBody", {})
                    })

        self.endpoints = endpoints
        logger.info(f"Discovered {len(endpoints)} endpoints")
        return endpoints

    # ---------------- PARAM EXTRACTION ----------------

    def _extract_params(self, details):

        params = []

        # QUERY / PATH / HEADER PARAMS
        for p in details.get("parameters", []):
            params.append({
                "name": p.get("name"),
                "in": p.get("in")  # query / path / header
            })

        # BODY PARAMS (IMPORTANT)
        request_body = details.get("requestBody", {})
        content = request_body.get("content", {})

        if "application/json" in content:
            schema = content["application/json"].get("schema", {})
            properties = schema.get("properties", {})

            for prop in properties:
                params.append({
                    "name": prop,
                    "in": "body"
                })

        return params

    # ---------------- DETAILS ----------------

    def get_endpoint_details(self, path: str, method: str) -> Dict[str, Any]:
        method = method.lower()
        spec = self.spec.get("paths", {}).get(path, {}).get(method, {})

        return {
            "params": self._extract_params(spec),
            "parameters": spec.get("parameters", []),
            "request_body": spec.get("requestBody", {}),
            "responses": spec.get("responses", {}),
            "security": spec.get("security", [])
        }

    # ---------------- SECURITY ----------------

    def get_security_schemes(self) -> Dict[str, Dict]:
        return self.spec.get("components", {}).get("securitySchemes", {})


def parse_api_spec(spec_path: str) -> APIParser:
    return APIParser(spec_path)