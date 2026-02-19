"""
API Parser Module
Parses OpenAPI/Swagger specifications and extracts endpoint information
for security testing and fuzzing.
"""

import os
import prance
import yaml
import json
from typing import Dict, List, Optional, Any
from pathlib import Path
import logging
from colorama import Fore, Style, init

init(autoreset=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class APIParser:
    """
    Parses OpenAPI/Swagger specification files and extracts information
    needed for API security testing.
    """

    def __init__(self, spec_path: str, base_url: Optional[str] = None):
        self.spec_path = Path(spec_path)
        self.spec = None
        self.base_url = None
        self.cli_base_url = base_url
        self.endpoints = []

        if not self.spec_path.exists():
            raise FileNotFoundError(f"Spec file not found: {spec_path}")

        self._parse_spec()
        logger.info(f"{Fore.GREEN}Successfully parsed API spec: {self.spec_path.name}")

    def _parse_spec(self):
        try:
            parser = prance.ResolvingParser(str(self.spec_path))
            self.spec = parser.specification
            self._extract_base_info()
        except Exception as e:
            logger.error(f"{Fore.RED}Failed to parse spec: {e}")
            raise ValueError(f"Invalid OpenAPI specification: {e}")

    def _extract_base_info(self):
        info = self.spec.get('info', {})
        self.api_title = info.get('title', 'Unknown API')
        self.api_version = info.get('version', '1.0.0')
        self.api_description = info.get('description', 'No description')

        self.base_url = self._resolve_base_url()

        logger.info(f"API: {self.api_title} v{self.api_version}")
        logger.info(f"Base URL: {self.base_url}")

    def _resolve_base_url(self) -> str:
        if self.cli_base_url:
            return self.cli_base_url.rstrip("/")

        env_url = os.getenv("AAVS_TARGET")
        if env_url:
            return env_url.rstrip("/")

        servers = self.spec.get("servers", [])
        if servers and "url" in servers[0]:
            return servers[0]["url"].rstrip("/")

        return "http://localhost:8000"

    def get_api_info(self) -> Dict[str, Any]:
        return {
            'title': self.api_title,
            'version': self.api_version,
            'description': self.api_description,
            'base_url': self.base_url
        }

    def get_all_endpoints(self) -> List[Dict[str, Any]]:
        endpoints = []
        paths = self.spec.get('paths', {})

        for path, methods in paths.items():
            for method, details in methods.items():
                if method.lower() in ['get', 'post', 'put', 'delete', 'patch', 'head', 'options']:
                    endpoint = {
                        'path': path,
                        'method': method.upper(),
                        'summary': details.get('summary', 'No summary'),
                        'description': details.get('description', 'No description'),
                        'operation_id': details.get('operationId', f"{method}_{path}"),
                        'tags': details.get('tags', []),
                        'deprecated': details.get('deprecated', False),
                    }
                    endpoints.append(endpoint)

        self.endpoints = endpoints
        logger.info(f"Found {len(endpoints)} endpoints")
        return endpoints

    def get_endpoint_details(self, path: str, method: str) -> Dict[str, Any]:
        method = method.lower()
        endpoint_spec = self.spec.get('paths', {}).get(path, {}).get(method, {})

        if not endpoint_spec:
            logger.warning(f"{Fore.YELLOW}Endpoint not found: {method.upper()} {path}")
            return {}

        return {
            'path': path,
            'method': method.upper(),
            'summary': endpoint_spec.get('summary', ''),
            'description': endpoint_spec.get('description', ''),
            'parameters': self._extract_parameters(endpoint_spec),
            'request_body': self._extract_request_body(endpoint_spec),
            'responses': self._extract_responses(endpoint_spec),
            'security': endpoint_spec.get('security', []),
            'tags': endpoint_spec.get('tags', []),
        }

    def _extract_parameters(self, endpoint_spec: Dict) -> Dict[str, List[Dict]]:
        parameters = {'path': [], 'query': [], 'header': [], 'cookie': []}

        for param in endpoint_spec.get('parameters', []):
            loc = param.get('in', 'query')
            schema = param.get('schema', {})

            info = {
                'name': param.get('name'),
                'required': param.get('required', False),
                'description': param.get('description', ''),
                'type': schema.get('type', 'string'),
                'format': schema.get('format'),
                'default': schema.get('default'),
                'enum': schema.get('enum'),
                'minimum': schema.get('minimum'),
                'maximum': schema.get('maximum'),
                'min_length': schema.get('minLength'),
                'max_length': schema.get('maxLength'),
                'pattern': schema.get('pattern'),
            }

            if loc in parameters:
                parameters[loc].append(info)

        return parameters

    def _extract_request_body(self, endpoint_spec: Dict) -> Optional[Dict]:
        rb = endpoint_spec.get('requestBody')
        if not rb:
            return None

        info = {
            'required': rb.get('required', False),
            'description': rb.get('description', ''),
            'content': {}
        }

        for media, spec in rb.get('content', {}).items():
            info['content'][media] = {
                'schema': spec.get('schema', {}),
                'examples': spec.get('examples', {})
            }

        return info

    def _extract_responses(self, endpoint_spec: Dict) -> Dict[str, Dict]:
        responses = {}
        for code, spec in endpoint_spec.get('responses', {}).items():
            responses[code] = {
                'description': spec.get('description', ''),
                'headers': spec.get('headers', {}),
                'content': spec.get('content', {})
            }
        return responses

    def get_security_schemes(self) -> Dict[str, Dict]:
        return self.spec.get('components', {}).get('securitySchemes', {})

    def print_summary(self):
        print(f"\n{Fore.CYAN}{'=' * 70}")
        print("API SPECIFICATION SUMMARY")
        print(f"{'=' * 70}{Style.RESET_ALL}\n")

        info = self.get_api_info()
        print(f"{Fore.GREEN}Title:{Style.RESET_ALL} {info['title']}")
        print(f"{Fore.GREEN}Version:{Style.RESET_ALL} {info['version']}")
        print(f"{Fore.GREEN}Base URL:{Style.RESET_ALL} {info['base_url']}\n")

        endpoints = self.get_all_endpoints()
        print(f"{Fore.YELLOW}Total Endpoints:{Style.RESET_ALL} {len(endpoints)}\n")

        for ep in endpoints:
            print(f"{ep['method']:6} {ep['path']}")

    def export_to_json(self, output_file: str):
        data = {
            'api_info': self.get_api_info(),
            'endpoints': self.get_all_endpoints(),
            'security_schemes': self.get_security_schemes()
        }

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)

        logger.info(f"{Fore.GREEN}Exported to: {output_file}")


def parse_api_spec(spec_path: str) -> APIParser:
    return APIParser(spec_path)


if __name__ == "__main__":
    parser = APIParser("examples/simple_api.yaml")
    parser.print_summary()
