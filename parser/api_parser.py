"""
API Parser Module
Supports:
- Local OpenAPI files (YAML / JSON)
- Remote OpenAPI discovery from base URLs
"""

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
        logger.info(f"{Fore.GREEN}Successfully loaded API specification")

    # --------------------------------------------------
    # SPEC LOADING
    # --------------------------------------------------

    def _load_local_spec(self):
        path = Path(self.spec_source)

        if not path.exists():
            raise FileNotFoundError(f"Spec file not found: {self.spec_source}")

        try:
            parser = prance.ResolvingParser(str(path))
            self.spec = parser.specification
        except Exception as e:
            raise ValueError(f"Invalid OpenAPI file: {e}")

    def _load_remote_spec(self):
        base = self.spec_source.rstrip("/")

        logger.info(f"Searching for OpenAPI spec on target server...")

        for path in self.COMMON_SPEC_PATHS:
            url = base + path

            try:
                r = requests.get(url, timeout=6)

                if r.status_code == 200 and "json" in r.headers.get("Content-Type", ""):
                    self.spec = r.json()
                    logger.info(f"{Fore.GREEN}Found spec at: {url}")
                    return

            except Exception:
                continue

        raise ValueError("No OpenAPI specification found on server")

    # --------------------------------------------------
    # BASE INFO
    # --------------------------------------------------

    def _extract_base_info(self):
        info = self.spec.get('info', {})

        self.api_title = info.get('title', 'Unknown API')
        self.api_version = info.get('version', '1.0.0')
        self.api_description = info.get('description', '')

        self.base_url = self._resolve_base_url()

    def _resolve_base_url(self) -> str:
        if self.cli_base_url:
            return self.cli_base_url.rstrip("/")

        env_url = os.getenv("AAVS_TARGET")
        if env_url:
            return env_url.rstrip("/")

        servers = self.spec.get("servers", [])
        if servers and "url" in servers[0]:
            return servers[0]["url"].rstrip("/")

        return self.spec_source.rstrip("/")

    # --------------------------------------------------
    # API INFO
    # --------------------------------------------------

    def get_api_info(self) -> Dict[str, Any]:
        return {
            'title': self.api_title,
            'version': self.api_version,
            'description': self.api_description,
            'base_url': self.base_url
        }

    # --------------------------------------------------
    # ENDPOINT EXTRACTION
    # --------------------------------------------------

    def get_all_endpoints(self) -> List[Dict[str, Any]]:
        endpoints = []
        paths = self.spec.get('paths', {})

        for path, methods in paths.items():
            for method, details in methods.items():
                if method.lower() in ["get", "post", "put", "delete", "patch", "head", "options"]:
                    endpoints.append({
                        "path": path,
                        "method": method.upper(),
                        "summary": details.get("summary", ""),
                        "description": details.get("description", ""),
                        "operation_id": details.get("operationId", ""),
                        "tags": details.get("tags", []),
                        "deprecated": details.get("deprecated", False)
                    })

        self.endpoints = endpoints
        logger.info(f"Discovered {len(endpoints)} endpoints")
        return endpoints

    # --------------------------------------------------
    # ENDPOINT DETAILS
    # --------------------------------------------------

    def get_endpoint_details(self, path: str, method: str) -> Dict[str, Any]:
        method = method.lower()
        spec = self.spec.get("paths", {}).get(path, {}).get(method, {})

        if not spec:
            return {}

        return {
            "parameters": spec.get("parameters", []),
            "request_body": spec.get("requestBody", {}),
            "responses": spec.get("responses", {}),
            "security": spec.get("security", [])
        }

    # --------------------------------------------------
    # SECURITY SCHEMES
    # --------------------------------------------------

    def get_security_schemes(self) -> Dict[str, Dict]:
        return self.spec.get("components", {}).get("securitySchemes", {})

    # --------------------------------------------------
    # EXPORT
    # --------------------------------------------------

    def export_to_json(self, output_file: str):
        data = {
            "api_info": self.get_api_info(),
            "endpoints": self.get_all_endpoints(),
            "security": self.get_security_schemes()
        }

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        logger.info(f"{Fore.GREEN}Exported results to {output_file}")


def parse_api_spec(spec_path: str) -> APIParser:
    return APIParser(spec_path)


if __name__ == "__main__":
    parser = APIParser("https://example.com")
    parser.get_all_endpoints()
